import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { render } from '@testing-library/react'
import { theme as antdTheme } from 'antd'
import { Route, Routes } from 'react-router-dom'

import { isThemeDocument, type ThemeDocument } from '../api/theme'
import * as session from '../auth/session'
import { AppShell } from '../components/AppShell'
import { LoginPage } from '../pages/LoginPage'
import { PublicBrandAssetImage, PublicBrandFavicon, publicBrandAssetUpdatedEvent } from '../components/PublicBrandAssetImage'
import { authResponse, principal } from '../test/fixtures'
import { renderWithProviders } from '../test/render'
import { ThemeProvider } from '../theme/ThemeProvider'
import { antdThemeConfig, brandCandidates, defaultAntdTokens, defaultThemeLayout, ThemeRuntimeContext, themeChangedEvent } from '../theme/runtime'

const sha = (digit: string) => digit.repeat(64)

function slateDocument(overrides: Partial<ThemeDocument['layout']> = {}): ThemeDocument {
  return {
    schema: 'cdnca.theme.rendered/v1', id: 'official.slate', version: '1.0.0', package_sha256: sha('a'),
    name: { 'zh-CN': '石板青', 'en-US': 'Slate' },
    antd_tokens: { ...defaultAntdTokens, colorPrimary: '#0f766e', colorLink: '#0f766e', borderRadius: 6 },
    css_variables: { '--cdnca-color-primary': '#0f766e', '--setting-primary': '#0f766e' },
    layout: { ...defaultThemeLayout, login_layout: 'centered', sidebar: 'dark', ...overrides },
    brand: { logo_dark: { url: `/v1/theme/assets/${sha('d')}`, mime_type: 'image/png', sha256: sha('d') } },
  }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  document.getElementById('cdnca-theme-stylesheet')?.remove()
  for (const key of ['cdncaTheme', 'cdncaThemeId', 'cdncaLook', 'cdncaMotion', 'cdncaRole']) delete document.documentElement.dataset[key]
})

describe('theme runtime', () => {
  it('reproduces the hard-coded ConfigProvider theme for the default tokens', () => {
    const config = antdThemeConfig(defaultAntdTokens, false)
    expect(config.token).toMatchObject({
      motion: true, colorPrimary: '#2d8cf0', colorLink: '#2d8cf0', colorLinkHover: '#57a3f3', colorText: '#515a6e',
      colorTextSecondary: '#808695', colorBorder: '#dcdee2', colorBgLayout: '#f5f7f9', borderRadius: 4, controlHeight: 32,
      fontSize: 14, lineHeight: 1.5,
    })
    expect(config.components?.Menu).toMatchObject({ itemBorderRadius: 0, itemHeight: 49, itemSelectedBg: '#f0faff', itemSelectedColor: '#2d8cf0' })
    expect(antdThemeConfig({ ...defaultAntdTokens, colorPrimary: '#0f766e' }, true).components?.Menu?.itemSelectedColor).toBe('#0f766e')
  })

  it('prefers the platform upload, then the theme image, then the fallback slot and built-in file', () => {
    const all = { logo: 1, logo_dark: 2, login_ad: 3, login_background: 4 }
    expect(brandCandidates('logo', null, all)).toEqual(['/v1/brand-assets/logo?v=1', '/dashboard/logo.png'])
    expect(brandCandidates('logo_dark', slateDocument(), all)).toEqual([
      '/v1/brand-assets/logo_dark?v=2', `/v1/theme/assets/${sha('d')}`, '/v1/brand-assets/logo?v=1', '/dashboard/logo-dark.png',
    ])
    expect(brandCandidates('login_background', null, all)).toEqual(['/v1/brand-assets/login_background?v=4', '/v1/brand-assets/login_ad?v=3', '/dashboard/login-background.jpeg'])
  })

  it('requests only the uploaded slots', () => {
    expect(brandCandidates('logo', null)).toEqual(['/dashboard/logo.png'])
    expect(brandCandidates('logo_dark', slateDocument(), {})).toEqual([`/v1/theme/assets/${sha('d')}`, '/dashboard/logo-dark.png'])
    expect(brandCandidates('logo_dark', slateDocument(), { logo: 7 })).toEqual([`/v1/theme/assets/${sha('d')}`, '/v1/brand-assets/logo?v=7', '/dashboard/logo-dark.png'])
    expect(brandCandidates('app_icon', null, { favicon: 2 })).toEqual(['/v1/brand-assets/favicon?v=2', '/dashboard/app-icon-180.png'])
  })
})

function TokenProbe() {
  const { token } = antdTheme.useToken()
  return <output aria-label="primary">{token.colorPrimary}</output>
}

describe('ThemeProvider', () => {
  it('loads the active theme, links its same-origin stylesheet and feeds ConfigProvider', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/v1/theme/current')) {
        return json({ schema: 'cdnca.theme.current/v1', revision: 3, theme_id: 'official.slate', version: '1.0.0', package_sha256: sha('a'),
          tokens_url: `/v1/theme/theme.${sha('b')}.json`, stylesheet_url: `/v1/theme/theme.${sha('c')}.css`, scope: 'platform' })
      }
      if (url.endsWith(`/v1/theme/theme.${sha('b')}.json`)) return json(slateDocument())
      throw new Error(`unexpected ${url}`)
    })
    render(<ThemeProvider><TokenProbe /></ThemeProvider>)

    expect(screen.getByLabelText('primary')).toHaveTextContent('#2d8cf0')
    await waitFor(() => expect(screen.getByLabelText('primary')).toHaveTextContent('#0f766e'))
    const link = document.getElementById('cdnca-theme-stylesheet') as HTMLLinkElement
    expect(link.getAttribute('href')).toBe(`/v1/theme/theme.${sha('c')}.css`)
    expect(link.rel).toBe('stylesheet')
    expect(document.documentElement.dataset.cdncaTheme).toBe(sha('a'))
    // A theme adds no script and no inline style.
    expect(document.querySelectorAll('script[src*="/v1/theme"], style[data-cdnca-theme]')).toHaveLength(0)
    expect(fetchSpy.mock.calls.map(([url]) => String(url))).toEqual(['/v1/theme/current', `/v1/theme/theme.${sha('b')}.json`])

    window.dispatchEvent(new Event(themeChangedEvent))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(4))
  })

  it('marks the root with the tech look, motion and role, and applies the role tokens', async () => {
    const tech: ThemeDocument = {
      ...slateDocument({ look: 'tech', motion: 'rich' }), id: 'official.tech',
      antd_tokens: { ...defaultAntdTokens, colorPrimary: '#2563eb' },
      antd_tokens_by_role: { user: { colorPrimary: '#0f172a' } },
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/v1/theme/current')) {
        return json({ schema: 'cdnca.theme.current/v1', revision: 3, theme_id: 'official.tech', version: '1.0.0', package_sha256: sha('a'),
          tokens_url: `/v1/theme/theme.${sha('b')}.json`, stylesheet_url: `/v1/theme/theme.${sha('c')}.css`, scope: 'platform' })
      }
      return json(tech)
    })
    render(<ThemeProvider><TokenProbe /></ThemeProvider>)
    const root = document.documentElement.dataset
    expect(root.cdncaRole).toBe('public')
    expect(root.cdncaLook).toBeUndefined()
    await waitFor(() => expect(root.cdncaLook).toBe('tech'))
    expect(root.cdncaMotion).toBe('rich')
    expect(root.cdncaThemeId).toBe('official.tech')
    expect(screen.getByLabelText('primary')).toHaveTextContent('#2563eb')

    const actor = principal({ scope_kind: 'tenant' })
    act(() => session.useSessionStore.getState().setSession(authResponse(actor), actor))
    await waitFor(() => expect(root.cdncaRole).toBe('user'))
    await waitFor(() => expect(screen.getByLabelText('primary')).toHaveTextContent('#0f172a'))
    act(() => session.resetSessionStore())
  })

  it('rejects a document with an unknown look or role token', () => {
    expect(isThemeDocument({ ...slateDocument(), layout: { ...slateDocument().layout, look: 'neon' } })).toBe(false)
    expect(isThemeDocument({ ...slateDocument(), antd_tokens_by_role: { guest: {} } })).toBe(false)
    expect(isThemeDocument({ ...slateDocument(), antd_tokens_by_role: { admin: { colorPrimary: 'red' } } })).toBe(false)
    expect(isThemeDocument({ ...slateDocument(), antd_tokens_by_role: { admin: { colorPrimary: '#123456' } } })).toBe(true)
  })

  it('keeps the default theme when the theme cannot be loaded or is malformed', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(json({
      schema: 'cdnca.theme.current/v1', revision: 1, theme_id: 'custom.x', version: '1.0.0', package_sha256: sha('a'),
      tokens_url: 'https://evil.example/theme.json', stylesheet_url: `/v1/theme/theme.${sha('c')}.css`, scope: 'platform',
    }))
    render(<ThemeProvider><TokenProbe /></ThemeProvider>)
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(screen.getByLabelText('primary')).toHaveTextContent('#2d8cf0')
    expect(document.getElementById('cdnca-theme-stylesheet')).toBeNull()
  })
})

describe('themed shell and login page', () => {
  it('renders the dark sidebar, themed logo, header links and footer from the layout slots', () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const view = renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document: slateDocument(), layout: slateDocument({
        header_links: [{ label: { 'zh-CN': '帮助中心' }, url: 'https://docs.example.test/' }], footer_text: { 'zh-CN': '© 示例平台' },
      }).layout }}>
        <Routes><Route element={<AppShell />}><Route path="*" element={<div />} /></Route></Routes>
      </ThemeRuntimeContext.Provider>,
      ['/admin-home'],
    )
    expect(view.container.querySelector('.app-shell')).toHaveClass('is-sidebar-dark')
    expect(view.container.querySelector('.shell-menu')).toHaveClass('ant-menu-dark')
    expect(view.container.querySelector('.shell-brand img')).toHaveAttribute('src', `/v1/theme/assets/${sha('d')}`)
    const links = screen.getByRole('navigation', { name: '主题链接' })
    expect(within(links).getByRole('link', { name: '帮助中心' })).toHaveAttribute('href', 'https://docs.example.test/')
    expect(within(links).getByRole('link', { name: '帮助中心' })).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.getByText('© 示例平台').tagName).toBe('FOOTER')
  })

  // fix-e1 #6: the product name comes from the theme (PA-26 white label), "cdnca" without one.
  it('names the product after the theme brand_name, cdnca by default', () => {
    const actor = principal({ scope_kind: 'platform', tenant_id: null, roles: ['platform_admin'], permissions: ['platform.admin'] })
    session.useSessionStore.getState().setSession(authResponse(actor), actor)
    const layout = slateDocument({ brand_name: { 'zh-CN': '示例云', 'en-US': 'Example Cloud' } }).layout
    const shell = renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document: slateDocument(), layout }}>
        <Routes><Route element={<AppShell />}><Route path="*" element={<div />} /></Route></Routes>
      </ThemeRuntimeContext.Provider>,
      ['/admin-home'],
    )
    expect(screen.getAllByAltText('示例云').length).toBeGreaterThan(0)
    expect(screen.queryByAltText('cdnca')).toBeNull()
    shell.unmount()
    const login = renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document: slateDocument(), layout }}>
        <LoginPage />
      </ThemeRuntimeContext.Provider>,
      ['/login'],
    )
    expect(screen.getByRole('heading', { level: 1, name: '示例云' })).toBeInTheDocument()
    login.unmount()
    renderWithProviders(<LoginPage />, ['/login'])
    expect(screen.getByRole('heading', { level: 1, name: 'cdnca' })).toBeInTheDocument()
  })

  it('switches the login layout and keeps the default split layout without a theme', () => {
    const themed = renderWithProviders(
      <ThemeRuntimeContext.Provider value={{ document: slateDocument(), layout: slateDocument({ footer_text: { 'zh-CN': '页脚' } }).layout }}>
        <LoginPage />
      </ThemeRuntimeContext.Provider>,
      ['/login'],
    )
    expect(themed.container.querySelector('.login-page')).toHaveClass('is-layout-centered')
    expect(themed.container.querySelector('.login-ad')).toBeNull()
    expect(screen.getByText('页脚')).toBeInTheDocument()
    themed.unmount()

    const plain = renderWithProviders(<LoginPage />, ['/login'])
    expect(plain.container.querySelector('.login-page')).toHaveClass('is-layout-split')
    expect(plain.container.querySelector('.login-ad img')).toHaveAttribute('src', '/dashboard/ad.jpeg')
  })
})

describe('PA-26 tenant themes', () => {
  it('sends the session to /v1/theme/current and reloads when the signed-in scope changes', async () => {
    const authorizations: (string | null)[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.endsWith('/v1/theme/current')) {
        authorizations.push(new Headers(init?.headers).get('Authorization'))
        return json({ schema: 'cdnca.theme.current/v1', revision: 1, theme_id: 'official.slate', version: '1.0.0', package_sha256: sha('a'),
          tokens_url: `/v1/theme/theme.${sha('b')}.json`, stylesheet_url: `/v1/theme/theme.${sha('c')}.css`, scope: 'tenant' })
      }
      if (url.endsWith(`/v1/theme/theme.${sha('b')}.json`)) return json(slateDocument())
      throw new Error(`unexpected ${url}`)
    })
    session.useSessionStore.getState().clearSession()
    render(<ThemeProvider><TokenProbe /></ThemeProvider>)
    await waitFor(() => expect(screen.getByLabelText('primary')).toHaveTextContent('#0f766e'))
    const tenant = principal({ scope_id: '11111111-1111-4111-8111-111111111111' })
    session.useSessionStore.getState().setSession(authResponse(tenant), tenant)
    await waitFor(() => expect(authorizations.length).toBeGreaterThanOrEqual(2))
    expect(authorizations[0]).toBeNull()
    expect(authorizations.at(-1)).toMatch(/^Bearer /)
  })

  it('never shows the platform upload under a tenant theme', () => {
    const document = slateDocument()
    document.brand.logo = { url: `/v1/theme/assets/${sha('e')}`, mime_type: 'image/png', sha256: sha('e') }
    const view = render(
      <ThemeRuntimeContext.Provider value={{ document, layout: document.layout, scope: 'tenant', brandAssets: { logo: 1 } }}>
        <PublicBrandAssetImage alt="brand" slot="logo" />
      </ThemeRuntimeContext.Provider>,
    )
    expect(screen.getByAltText('brand')).toHaveAttribute('src', `/v1/theme/assets/${sha('e')}`)
    view.unmount()
    render(
      <ThemeRuntimeContext.Provider value={{ document, layout: document.layout, scope: 'platform', brandAssets: { logo: 1 } }}>
        <PublicBrandAssetImage alt="brand" slot="logo" />
      </ThemeRuntimeContext.Provider>,
    )
    expect(screen.getByAltText('brand')).toHaveAttribute('src', '/v1/brand-assets/logo?v=1')
  })

  const brandSources = () => Array.from(window.document.querySelectorAll<HTMLImageElement>('img'))
    .map((image) => image.getAttribute('src') ?? '').filter((src) => src.startsWith('/v1/brand-assets/'))
  const currentWith = (brandAssets?: Record<string, number>) => json({
    schema: 'cdnca.theme.current/v1', revision: 3, theme_id: 'official.slate', version: '1.0.0', package_sha256: sha('a'),
    tokens_url: `/v1/theme/theme.${sha('b')}.json`, stylesheet_url: `/v1/theme/theme.${sha('c')}.css`, scope: 'platform',
    ...(brandAssets ? { brand_assets: brandAssets } : {}),
  })

  it('requests no platform upload the platform never made', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/v1/theme/current')) return currentWith({})
      if (url.endsWith(`/v1/theme/theme.${sha('b')}.json`)) return json(slateDocument())
      throw new Error(`unexpected ${url}`)
    })
    const view = render(<ThemeProvider><PublicBrandFavicon /><PublicBrandAssetImage alt="brand" slot="logo" /><PublicBrandAssetImage alt="ad" slot="login_ad" /></ThemeProvider>)
    expect(brandSources()).toEqual([])
    await waitFor(() => expect(window.document.documentElement.dataset.cdncaThemeId).toBe('official.slate'))
    expect(brandSources()).toEqual([])
    expect(screen.getByAltText('brand')).toHaveAttribute('src', '/dashboard/logo.png')
    expect(screen.getByAltText('ad')).toHaveAttribute('src', '/dashboard/ad.jpeg')
    expect(fetchSpy.mock.calls.map(([url]) => String(url)).filter((url) => url.includes('/v1/brand-assets/'))).toEqual([])
    view.unmount()
  })

  it('requests an uploaded slot with its revision and picks up a new upload at once', async () => {
    let revisions: Record<string, number> = { favicon: 2, logo: 5 }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/v1/theme/current')) return currentWith(revisions)
      if (url.endsWith(`/v1/theme/theme.${sha('b')}.json`)) return json(slateDocument())
      throw new Error(`unexpected ${url}`)
    })
    const view = render(<ThemeProvider><PublicBrandFavicon /><PublicBrandAssetImage alt="brand" slot="logo" /></ThemeProvider>)
    await waitFor(() => expect(screen.getByAltText('brand')).toHaveAttribute('src', '/v1/brand-assets/logo?v=5'))
    // app_icon falls back to the uploaded favicon; login_ad was never uploaded.
    expect(brandSources().sort()).toEqual(['/v1/brand-assets/favicon?v=2', '/v1/brand-assets/favicon?v=2', '/v1/brand-assets/logo?v=5'])

    revisions = { favicon: 3, logo: 5 }
    act(() => { window.dispatchEvent(new Event(publicBrandAssetUpdatedEvent)) })
    await waitFor(() => expect(brandSources()).toContain('/v1/brand-assets/favicon?v=3'))
    expect(brandSources()).not.toContain('/v1/brand-assets/favicon?v=2')
    view.unmount()
  })

  it('does not probe again when the theme object changes but its content does not', () => {
    const document = slateDocument()
    const value = (doc: ThemeDocument) => ({ document: doc, layout: doc.layout, scope: 'platform' as const, brandAssets: { favicon: 2, logo: 5 } })
    const tree = (doc: ThemeDocument) => (
      <ThemeRuntimeContext.Provider value={value(doc)}>
        <PublicBrandFavicon />
        <PublicBrandAssetImage alt="brand" slot="logo" />
      </ThemeRuntimeContext.Provider>
    )
    const assigned: string[] = []
    const descriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src')!
    const spy = vi.spyOn(HTMLImageElement.prototype, 'src', 'set').mockImplementation(function (this: HTMLImageElement, next: string) {
      assigned.push(next)
      descriptor.set!.call(this, next)
    })
    const view = render(tree(document))
    const probes = Array.from(window.document.querySelectorAll('img[aria-hidden="true"]'))
    expect(assigned.sort()).toEqual(['/v1/brand-assets/favicon?v=2', '/v1/brand-assets/favicon?v=2', '/v1/brand-assets/logo?v=5'])
    // The logo fell back to the built-in file.
    fireEvent.error(screen.getByAltText('brand'))
    expect(screen.getByAltText('brand')).toHaveAttribute('src', '/dashboard/logo.png')
    const before = assigned.length

    view.rerender(tree(structuredClone(document)))
    view.rerender(tree(structuredClone(document)))
    expect(assigned).toHaveLength(before)
    expect(Array.from(window.document.querySelectorAll('img[aria-hidden="true"]'))).toEqual(probes)
    expect(screen.getByAltText('brand')).toHaveAttribute('src', '/dashboard/logo.png')
    spy.mockRestore()
    view.unmount()
  })

  it('points favicon and app icon at the theme images', () => {
    const document = slateDocument()
    document.brand.favicon = { url: `/v1/theme/assets/${sha('f')}`, mime_type: 'image/x-icon', sha256: sha('f') }
    document.brand.app_icon = { url: `/v1/theme/assets/${sha('9')}`, mime_type: 'image/png', sha256: sha('9') }
    const view = render(
      <ThemeRuntimeContext.Provider value={{ document, layout: document.layout, scope: 'tenant' }}>
        <PublicBrandFavicon />
      </ThemeRuntimeContext.Provider>,
    )
    const probes = Array.from(window.document.querySelectorAll<HTMLImageElement>('img[aria-hidden="true"]'))
    expect(probes.map((probe) => probe.getAttribute('src'))).toEqual([`/v1/theme/assets/${sha('f')}`, `/v1/theme/assets/${sha('9')}`])
    probes.forEach((probe) => probe.dispatchEvent(new Event('load')))
    const icon = window.document.head.querySelector('link[rel="icon"]')
    const touch = window.document.head.querySelector('link[rel="apple-touch-icon"]')
    expect(icon).toHaveAttribute('href', `/v1/theme/assets/${sha('f')}`)
    expect(icon).toHaveAttribute('type', 'image/x-icon')
    expect(touch).toHaveAttribute('href', `/v1/theme/assets/${sha('9')}`)
    view.unmount()
    expect(window.document.head.querySelector('link[rel="apple-touch-icon"]')).toBeNull()
  })
})
