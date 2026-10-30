// fix-brandkit：打包安装后的默认品牌就是 cdnca。index.html 标题与图标、每个品牌槽位的内置回退
// 都指向 public/ 里真实存在的 cdnca 资源；各前端不再出现旧名 "cdn 4.0"。
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

import { brandCandidates } from '../theme/runtime'

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

  it('no front end still names itself cdn 4.0', () => {
    const files = ['web/index.html']
    for (const file of files) expect(readFileSync(resolve(apps, file), 'utf8'), file).not.toMatch(/cdn ?4\.0/i)
  })
})
