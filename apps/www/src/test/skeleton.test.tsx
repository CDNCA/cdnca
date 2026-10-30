import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { App } from '../App'
import { render as ssr, urls } from '../entry-server'
import { href, splitPath } from '../i18n'
import { allPages, NAV } from '../routes'
import { LINKS } from '../site'

describe('路由与语言', () => {
  it('splitPath 区分中英文前缀', () => {
    expect(splitPath('/')).toEqual({ lang: 'zh', path: '/' })
    expect(splitPath('/en/')).toEqual({ lang: 'en', path: '/' })
    expect(splitPath('/en/docs/install-node/')).toEqual({ lang: 'en', path: '/docs/install-node' })
    expect(splitPath('/docs/index.html')).toEqual({ lang: 'zh', path: '/docs' })
    expect(href('en', '/')).toBe('/en/')
    expect(href('zh', '/docs')).toBe('/docs')
  })

  it('每个页面中英各出一个 URL', () => {
    expect(urls()).toHaveLength(allPages().length * 2)
  })

  it.each(allPages().flatMap((p) => [href('zh', p.path), href('en', p.path)]))('%s 预渲染含 title/description/hreflang 与唯一 h1', (url) => {
    const r = ssr(url)
    expect(r.head).toMatch(/<title>[^<]+<\/title>/)
    expect(r.head).toMatch(/<meta name="description" content="[^"]{20,}"/)
    expect(r.head).toContain('hreflang="zh-CN"')
    expect(r.head).toContain('hreflang="en"')
    expect(r.html.match(/<h1[\s>]/g)).toHaveLength(1)
    expect(r.html).toContain('id="main"')
  })

  it('未知路径渲染 404 且 noindex', () => {
    const r = ssr('/no-such-page')
    expect(r.head).toContain('noindex')
    expect(r.html).toContain('页面不存在')
  })
})

describe('布局', () => {
  it('导航、登录/注册指向授权端，语言切换指向同一页', () => {
    render(<App pathname="/docs" />)
    const nav = screen.getByRole('navigation', { name: '主导航' })
    for (const n of NAV) expect(within(nav).getByRole('link', { name: n.label.zh })).toHaveAttribute('href', n.path)
    expect(within(nav).getByRole('link', { name: '使用文档' })).toHaveAttribute('aria-current', 'page')
    expect(within(nav).getByRole('link', { name: '登录' })).toHaveAttribute('href', 'https://auth.cdnca.com/')
    expect(within(nav).getByRole('link', { name: '注册' })).toHaveAttribute('href', 'https://auth.cdnca.com/console/register')
    expect(within(nav).getByRole('link', { name: 'Switch to English' })).toHaveAttribute('href', '/en/docs')
    expect(LINKS.login.startsWith('https://auth.cdnca.com')).toBe(true)
  })

  it('英文页导航带 /en 前缀', () => {
    render(<App pathname="/en/docs" />)
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(within(nav).getByRole('link', { name: 'Features' })).toHaveAttribute('href', '/en/features')
    expect(within(nav).getByRole('link', { name: '切换到中文' })).toHaveAttribute('href', '/docs')
    expect(within(nav).getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', 'https://auth.cdnca.com/')
  })

  it('有跳到正文链接，移动端菜单按钮可用键盘切换', async () => {
    render(<App pathname="/" />)
    expect(screen.getByRole('link', { name: '跳到正文' })).toHaveAttribute('href', '#main')
    const btn = screen.getByRole('button', { name: '菜单' })
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    btn.focus()
    await userEvent.keyboard('{Enter}')
    expect(btn).toHaveAttribute('aria-expanded', 'true')
  })
})
