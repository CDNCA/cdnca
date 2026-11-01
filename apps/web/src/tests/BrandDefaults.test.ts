// fix-brandkit：打包安装后的默认品牌就是 cdnca。index.html 标题与图标、每个品牌槽位的内置回退
// 都指向 public/ 里真实存在的 cdnca 资源；各前端不再出现旧名 "cdn 4.0"。
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

import { brandCandidates, builtInBrandAsset } from '../theme/runtime'

const web = resolve(__dirname, '../..')
const apps = resolve(web, '..')
const publicFile = (url: string) => resolve(web, 'public', url.replace(/^(\/dashboard)?\//, ''))

describe('cdnca default brand', () => {
  it('index.html is titled cdnca and links the bundled icons', () => {
    const html = readFileSync(resolve(web, 'index.html'), 'utf8')
    expect(html).toContain('<title>cdnca</title>')
    // Public files are written from the root: Vite adds the /dashboard/ base
    // (writing /dashboard/ here would become /dashboard/dashboard/ and 404 to HTML).
    for (const href of ['/favicon.png', '/app-icon-180.png']) {
      expect(html).toContain(`href="${href}"`)
      expect(existsSync(publicFile(href))).toBe(true)
    }
    expect(html).not.toContain('href="/dashboard/')
  })

  it('every brand slot falls back to its own bundled file', () => {
    const builtIn = {
      logo: '/dashboard/logo.png',
      logo_dark: '/dashboard/logo-dark.png',
      login_ad: '/dashboard/ad.jpeg',
      login_background: '/dashboard/login-background.jpeg',
      favicon: '/dashboard/favicon.png',
      app_icon: '/dashboard/app-icon-180.png',
    } as const
    for (const [slot, file] of Object.entries(builtIn)) {
      expect(brandCandidates(slot as keyof typeof builtIn, null).at(-1)).toBe(file)
      expect(existsSync(publicFile(file))).toBe(true)
    }
  })

  // 内置登录广告图的文案画在位图里，英文/繁体用各自导出的图；上传或主题图不按语言替换。
  it('the built-in login ad follows the language, a custom one does not', () => {
    expect(brandCandidates('login_ad', null, {}, 'en-US')).toEqual(['/dashboard/ad-en.jpeg'])
    expect(brandCandidates('login_ad', null, {}, 'zh-TW')).toEqual(['/dashboard/ad-zh-TW.jpeg'])
    expect(brandCandidates('login_ad', null, {}, 'zh-CN')).toEqual(['/dashboard/ad.jpeg'])
    expect(builtInBrandAsset('login_ad', 'en')).toBe('/dashboard/ad-en.jpeg')
    expect(builtInBrandAsset('login_ad')).toBe('/dashboard/ad.jpeg')
    expect(builtInBrandAsset('logo', 'en-US')).toBe('/dashboard/logo.png')
    expect(brandCandidates('login_ad', null, { login_ad: 3 }, 'en-US')).toEqual(['/v1/brand-assets/login_ad?v=3', '/dashboard/ad-en.jpeg'])
    // login_background 回落到 login_ad 的上传，但内置图仍是自己的背景图（无文字）。
    expect(brandCandidates('login_background', null, {}, 'en-US')).toEqual(['/dashboard/login-background.jpeg'])
    for (const file of ['/dashboard/ad-en.jpeg', '/dashboard/ad-zh-TW.jpeg']) expect(existsSync(publicFile(file))).toBe(true)
  })

  it('the login ad image shows the upload first in any language', () => {
    const custom = { login_ad: 5 }
    for (const locale of ['zh-CN', 'zh-TW', 'en-US']) {
      expect(brandCandidates('login_ad', null, custom, locale)[0]).toBe('/v1/brand-assets/login_ad?v=5')
    }
  })

  it('no front end still names itself cdn 4.0', () => {
    const files = ['web/index.html']
    for (const file of files) expect(readFileSync(resolve(apps, file), 'utf8'), file).not.toMatch(/cdn ?4\.0/i)
  })
})
