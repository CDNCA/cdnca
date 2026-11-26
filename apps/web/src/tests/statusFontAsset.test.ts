import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { afterAll, describe, expect, it } from 'vitest'

// 公开状态页 /status/ 的样式表把字体写成根路径 /assets/fonts/inter-latin-var.woff2，
// 主控构建（base /dashboard/）里没有这个文件，部署后字体 404。这里用 vite.config.ts 的 base 与
// status 入口真实构建一次，再按主控 nginx 的静态资源 location（原生安装 install-control.sh、
// 容器 nginx.conf）把每个字体 URL 映射回构建目录，证明文件确实在、会被提供。
const webRoot = resolve(__dirname, '../..')
const hosts = {
  'scripts/install-control.sh': resolve(webRoot, '../../scripts/install-control.sh'),
  'apps/web/nginx.conf': resolve(webRoot, 'nginx.conf'),
}

/** The static asset location of a management nginx config: its regex, rewrite and try_files root semantics. */
function staticAssetRoute(source: string) {
  const text = source.replace(/\\\$/g, '$')
  const match = /location ~\* (\^\/\(\?:dashboard\/\)\?\(\?:assets\/\S+) \{\s*rewrite (\S+) (\S+) break;\s*try_files \$uri =404;/.exec(text)
  if (!match) throw new Error('static asset location not found')
  return { location: new RegExp(match[1], 'i'), rewrite: new RegExp(match[2]), to: match[3] }
}

// esbuild 不能在 jsdom 环境里跑（TextEncoder 不变式），构建放到子进程：读 vite.config.ts 的 base 与 status 入口，只构建这个入口。
const buildScript = `
import { build, loadConfigFromFile } from 'vite'
const [root, outDir] = process.argv.slice(1)
const { config } = await loadConfigFromFile({ command: 'build', mode: 'production' }, 'vite.config.ts', root)
const input = { status: config.build.rollupOptions.input.status }
await build({ configFile: false, root, base: config.base, logLevel: 'silent', build: { outDir, emptyOutDir: true, rollupOptions: { input } } })
process.stdout.write(JSON.stringify({ base: config.base }))
`

const outDir = mkdtempSync(join(tmpdir(), 'cdnca-status-font-'))
afterAll(() => rmSync(outDir, { recursive: true, force: true }))

describe('public status page font', () => {
  it('builds every font URL to a file the management nginx serves', async () => {
    const { base } = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', buildScript, webRoot, outDir], { cwd: webRoot, encoding: 'utf8' })) as { base: string }
    expect(base).toBe('/dashboard/')

    const html = readFileSync(join(outDir, 'status/index.html'), 'utf8')
    const sheets = [...html.matchAll(/<link rel="stylesheet"[^>]*href="([^"]+)"/g)].map((item) => item[1])
    expect(sheets.length).toBeGreaterThan(0)
    const fonts = sheets.flatMap((href) => {
      expect(href.startsWith(base)).toBe(true)
      const css = readFileSync(join(outDir, href.slice(base.length)), 'utf8')
      return [...css.matchAll(/url\(["']?([^"')]+\.woff2)["']?\)/g)].map((item) => item[1])
    })
    expect(fonts.some((url) => /inter-latin-var/.test(url))).toBe(true)

    for (const [name, file] of Object.entries(hosts)) {
      const route = staticAssetRoute(readFileSync(file, 'utf8'))
      for (const url of fonts) {
        expect(url, `${name}: ${url}`).toMatch(/^\/dashboard\/assets\//)
        expect(route.location.test(url), `${name} location matches ${url}`).toBe(true)
        const path = url.replace(route.rewrite, route.to.replace(/\$(\d)/g, '$$$1'))
        expect(existsSync(join(outDir, path)), `${name}: ${url} -> ${path}`).toBe(true)
      }
    }
  }, 120_000)
})
