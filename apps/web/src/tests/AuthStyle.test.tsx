import { render, waitFor } from '@testing-library/react'

import type { ThemeDocument } from '../api/theme'
import { applyAuthStyle, authStyleAttribute, loadAuthStyle, sanitizeAuthCSS, useAuthStyle } from '../theme/authStyle'
import { defaultThemeLayout, ThemeRuntimeContext } from '../theme/runtime'

// Theme plugin C auth_style: the user console plugin's CSS for the platform
// sign-in pages goes into its own <style>; anything that is not plain CSS is
// dropped whole.

const imageURL = `/v1/theme/auth-style/assets/${'e'.repeat(64)}`
const injected = () => document.head.querySelectorAll(`style[${authStyleAttribute}]`)

afterEach(() => injected().forEach((node) => node.remove()))

describe('auth_style sanitizer', () => {
  it('keeps plain CSS and same-origin plugin images', () => {
    const css = `.login-page { background: #0b1020 url("${imageURL}") no-repeat; }\n.login-panel { border-radius: 12px }`
    expect(sanitizeAuthCSS(css)).toBe(css)
    const inline = '.login-ad{background-image:url("data:image/png;base64,iVBORw0KGgo=")}'
    expect(sanitizeAuthCSS(inline)).toBe(inline)
    expect(sanitizeAuthCSS('.a{background:url("data:text/html;base64,PHNjcmlwdD4=")}')).toBe('')
  })

  it('drops the whole stylesheet on script, markup or remote loading', () => {
    for (const css of [
      '.a{}</style><script>alert(1)</script>',
      '.a{} <script src="x"></script>',
      '.a{} < SCRIPT >',
      '.a{}</ style>',
      '@import url("https://evil.example/x.css");',
      '@charset "utf-7";',
      '.a{width:expression(alert(1))}',
      '.a{background:url(javascript:alert(1))}',
      '.a{background:url("https://evil.example/track.png")}',
      '.a{background:url(//evil.example/x)}',
      '.a{background:url(/v1/admin/users)}',
      '.a{behavior:url(x.htc)}',
      '.a{-moz-binding:url(x.xml)}',
      '.a{content:"\\3c script"}',
      '.a{content:"\\\\"}',
      '.a{background:url(vbscript:x)}',
      'html[data-cdnca-role=admin] .a{color:red}',
      '.a{background:url(/v1/theme/../admin)}',
      '<!-- .a{} -->',
      '.a{background:url( unbalanced',
    ]) {
      expect(sanitizeAuthCSS(css)).toBe('')
    }
    expect(sanitizeAuthCSS(42)).toBe('')
    expect(sanitizeAuthCSS('a'.repeat((256 << 10) + 1))).toBe('')
  })
})

describe('auth_style injection', () => {
  it('injects one <style> as text and removes it on cleanup', () => {
    const cleanup = applyAuthStyle('.login-panel{color:#123456}')
    expect(injected()).toHaveLength(1)
    expect(injected()[0].textContent).toBe('.login-panel{color:#123456}')
    expect(injected()[0].children).toHaveLength(0)
    // A second application replaces it.
    applyAuthStyle('.login-panel{color:#654321}')
    expect(injected()).toHaveLength(1)
    cleanup()
    applyAuthStyle('')
    expect(injected()).toHaveLength(0)
  })

  it('injects nothing for a stylesheet with <script', () => {
    applyAuthStyle('.a{}</style><script>alert(1)</script>')
    expect(injected()).toHaveLength(0)
    expect(document.head.querySelector('script')).toBeNull()
  })

  it('loads the style without credentials and ignores failures and foreign image URLs', async () => {
    const ok = vi.fn().mockResolvedValue(new Response(JSON.stringify({ css: '.a{}', images: { bg: imageURL, evil: 'https://evil.example/x.png' } }), { status: 200 }))
    expect(await loadAuthStyle('/v1/theme/auth-style', ok)).toEqual({ css: '.a{}', images: { bg: imageURL } })
    expect(ok.mock.calls[0][0]).toBe('/v1/theme/auth-style')
    expect(ok.mock.calls[0][1]).toMatchObject({ credentials: 'omit' })
    expect(await loadAuthStyle('/v1/theme/auth-style', vi.fn().mockResolvedValue(new Response(null, { status: 204 })))).toBeNull()
    expect(await loadAuthStyle('/v1/theme/auth-style', vi.fn().mockResolvedValue(new Response('{"css":1}', { status: 200 })))).toBeNull()
    expect(await loadAuthStyle('/v1/theme/auth-style', vi.fn().mockRejectedValue(new Error('offline')))).toBeNull()
    // Only the theme's own auth style path is fetched.
    const never = vi.fn()
    expect(await loadAuthStyle('https://evil.example/x.json', never)).toBeNull()
    expect(await loadAuthStyle('/v1/admin/users', never)).toBeNull()
    expect(never).not.toHaveBeenCalled()
  })

  function Page() { useAuthStyle(); return <form aria-label="login" /> }
  const withTheme = (auth_style_url?: string) => (
    <ThemeRuntimeContext.Provider value={{ document: { auth_style_url } as ThemeDocument, layout: defaultThemeLayout }}><Page /></ThemeRuntimeContext.Provider>
  )

  it('applies the style while a sign-in page is mounted', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ css: '.login-panel{color:#123456}', images: {} }), { status: 200 }))
    const { unmount } = render(withTheme(`/v1/theme/auth-style.${'f'.repeat(64)}.json`))
    await waitFor(() => expect(injected()).toHaveLength(1))
    expect(String(fetchSpy.mock.calls[0][0])).toBe(`/v1/theme/auth-style.${'f'.repeat(64)}.json`)
    unmount()
    expect(injected()).toHaveLength(0)
  })

  it('requests nothing when the theme has no auth style', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    render(withTheme(undefined))
    render(<Page />)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(injected()).toHaveLength(0)
  })
})
