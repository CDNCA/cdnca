// node --test packages/site-theme-kit/test/
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, describe, test } from 'node:test'

import { main } from '../bin/cdnca-site-theme.mjs'
import { buildContent, pack } from '../lib/pack.mjs'
import { createPreviewServer, SANDBOX_CSP } from '../lib/preview.mjs'
import { checkAuthCSS, checkContent, scanFile, validBundlePath } from '../lib/rules.mjs'
import { scaffold, scaffoldFiles, TEMPLATES } from '../lib/scaffold.mjs'

const repo = resolve(import.meta.dirname, '../../..')
const EXAMPLES = ['shield-blue', 'honey-orange'].map((name) => join(repo, 'examples/site-themes', name))
const temp = mkdtempSync(join(tmpdir(), 'site-theme-kit-'))
after(() => rmSync(temp, { recursive: true, force: true }))

const codes = (findings) => findings.items.map((item) => item.code)
const contentOf = (dir) => Buffer.from(`${JSON.stringify(buildContent(dir).content)}\n`)

describe('脚手架', () => {
  for (const template of TEMPLATES) {
    test(`${template} 模板通过预检并能打包`, () => {
      const dir = join(temp, `init-${template.replace('+', '-')}`)
      scaffold(dir, { template, pluginID: 'acme.dev.ocean', name: '海蓝' })
      const content = JSON.parse(contentOf(dir))
      assert.deepEqual(content.applies_to, template.split('+'))
      assert.equal(content.id, 'market.acme.dev.ocean')
      assert.equal('console_theme' in content, template.includes('user'))
      assert.equal('site_bundle' in content, template.includes('site'))
      assert.equal('content_schema' in content, template.includes('site'))
      assert.equal('supply_chain' in content, false, 'supply_chain 只用于 manifest，不进 content')
      assert.deepEqual(codes(checkContent(contentOf(dir), { pluginID: 'acme.dev.ocean' })), [])
      const out = pack(dir)
      assert.deepEqual(out.findings, [])
      assert.deepEqual(out.warnings, [])
    })
  }

  test('拒绝非法插件 ID 与已有内容的目录', () => {
    assert.throws(() => scaffoldFiles({ template: 'site', pluginID: 'Acme' }), /plugin id/)
    assert.throws(() => scaffoldFiles({ template: 'admin', pluginID: 'acme.dev.x' }), /template/)
    const dir = join(temp, 'init-site')
    assert.throws(() => scaffold(dir, { template: 'site', pluginID: 'acme.dev.ocean' }), /not empty/)
  })

  test('CLI 用法错误退出 2', async () => {
    assert.equal(await main(['init', join(temp, 'x'), '--template', 'admin', '--plugin-id', 'acme.dev.x']), 2)
    assert.equal(await main(['nope']), 2)
  })
})

describe('pack', () => {
  for (const dir of EXAMPLES) {
    test(`${dir.split('/').pop()} 输出稳定（两次打包逐字节相同）`, () => {
      const a = pack(dir, { outDir: join(temp, `${dir.split('/').pop()}-a`) })
      const b = pack(dir, { outDir: join(temp, `${dir.split('/').pop()}-b`) })
      assert.deepEqual(a.findings, [])
      assert.equal(a.contentSHA256, b.contentSHA256)
      assert.equal(a.manifestSHA256, b.manifestSHA256)
      assert.deepEqual(readFileSync(a.contentPath), readFileSync(b.contentPath))
      const manifest = JSON.parse(readFileSync(a.manifestPath, 'utf8'))
      assert.equal(manifest.spec.entrypoint.type, 'theme')
      assert.equal(manifest.spec.entrypoint.sha256, a.contentSHA256)
      assert.equal(manifest.spec.configuration_schema.sha256, a.schemaSHA256)
      assert.deepEqual(manifest.spec.permissions, ['platform.themes.provide'])
      assert.match(manifest.spec.supply_chain.sbom_sha256, /^[a-f0-9]{64}$/)
      assert.equal(manifest.integrity, undefined, '签名交给 cdnca-plugin sign-manifest')
      const content = JSON.parse(readFileSync(a.contentPath, 'utf8'))
      assert.equal(content.id, `market.${manifest.metadata.id}`)
      assert.equal(content.version, manifest.metadata.version)
      assert.ok(a.contentBytes < 8 << 20)
      const paths = content.site_bundle.files.map((f) => f.path)
      assert.deepEqual(paths, [...paths].sort(), '文件按路径排序')
    })
  }

  test('--version 同时改 content 与 manifest 版本', () => {
    const out = pack(EXAMPLES[0], { outDir: join(temp, 'versioned'), version: '1.2.3' })
    assert.equal(JSON.parse(readFileSync(out.contentPath, 'utf8')).version, '1.2.3')
    assert.equal(JSON.parse(readFileSync(out.contentPath, 'utf8')).console_theme.version, '1.2.3')
    assert.equal(JSON.parse(readFileSync(out.manifestPath, 'utf8')).metadata.version, '1.2.3')
  })

  test('预检不通过时不写 manifest', () => {
    const dir = join(temp, 'bad-pack')
    scaffold(dir, { template: 'site', pluginID: 'acme.dev.bad' })
    writeFileSync(join(dir, 'site/index.html'), '<script src="https://cdn.example.com/x.js"></script>')
    const out = pack(dir)
    assert.deepEqual(out.findings.map((x) => x.code), ['site_theme.bundle_external_script'])
    assert.equal(out.manifestPath, undefined)
  })
})

describe('页面包规则', () => {
  const cases = [
    ['后台路径', 'js', 'location.href = "/dashboard/"', 'bundle_dashboard'],
    ['后台其他页', 'html', '<a href="/dashboard/site/list">x</a>', 'bundle_dashboard'],
    ['登录页加后缀', 'html', '<a href="/dashboard/login-admin">x</a>', 'bundle_dashboard'],
    ['其他 /v1 接口', 'js', 'fetch("/v1/auth/me")', 'bundle_api'],
    ['转义斜线的 /v1', 'js', 'fetch("\\/v1\\/sites")', 'bundle_api'],
    ['资源路径爬目录', 'js', 'fetch("/v1/control-site/assets/../admin")', 'bundle_api'],
    ['service worker', 'js', 'navigator.serviceWorker.register("sw.js")', 'bundle_service_worker'],
    ['管理端选择器', 'css', 'html[data-cdnca-role="admin"] body { color: red }', 'bundle_admin'],
    ['base 标签', 'html', '<base href="/">', 'bundle_base'],
    ['外链脚本', 'html', '<script src="https://cdn.example.com/a.js"></script>', 'bundle_external_script'],
    ['协议相对外链', 'html', '<script src="//cdn.example.com/a.js"></script>', 'bundle_external_script'],
    ['modulepreload 外链', 'html', '<link rel="modulepreload" href="https://cdn.example.com/a.js">', 'bundle_external_script'],
    ['外链 import', 'mjs', 'import x from "https://cdn.example.com/x.mjs"', 'bundle_external_script'],
  ]
  for (const [name, ext, text, code] of cases) {
    test(`拒绝：${name}`, () => assert.equal(scanFile(ext, Buffer.from(text)), code))
  }
  test('放行两个公开接口、相对脚本与图片文件', () => {
    assert.equal(scanFile('js', Buffer.from('fetch("/v1/control-site/content"); img.src = "/v1/control-site/assets/" + sha')), '')
    assert.equal(scanFile('html', Buffer.from('<script src="assets/site.js"></script><link rel="stylesheet" href="https://fonts.example.com/a.css">')), '')
    assert.equal(scanFile('png', Buffer.from('/dashboard')), '', '二进制文件不扫描')
    assert.equal(scanFile('html', Buffer.from('<a href="/dashboard/login">登录</a><a href="/dashboard/register?from=site">注册</a>' +
      '<a href="/dashboard/forgot-password#top">找回</a>')), '', '三个平台登录页可以链接')
  })
  test('路径规则', () => {
    for (const ok of ['index.html', 'assets/a-b_c.1.js']) assert.ok(validBundlePath(ok), ok)
    for (const bad of ['/index.html', '../x.html', 'a/../b.html', 'a//b.html', 'C:\\x.html', '.env', 'a/.hidden/b.js', 'a b.html']) {
      assert.ok(!validBundlePath(bad), bad)
    }
  })
  test('登录页样式规则', () => {
    assert.equal(checkAuthCSS('.cdnca-auth-card { border-radius: 12px; background: url(data:image/png;base64,AAAA) }'), '')
    assert.equal(checkAuthCSS('@import "x.css";'), 'auth_style_css')
    assert.equal(checkAuthCSS('.a { background: url(https://cdn.example.com/a.png) }'), 'auth_style_url')
    assert.equal(checkAuthCSS('.a { content: "\\2f" }'), 'auth_style_css')
    assert.equal(checkAuthCSS('html[data-cdnca-role="admin"] .a { color: red }'), 'admin_forbidden')
  })
})

describe('整包规则', () => {
  const base = () => JSON.parse(contentOf(EXAMPLES[0]))
  const check = (pkg) => codes(checkContent(Buffer.from(JSON.stringify(pkg))))
  test('第三方不能声明 admin，也不能带 admin 令牌', () => {
    assert.deepEqual(check({ ...base(), applies_to: ['admin', 'user', 'site'] }), ['site_theme.admin_forbidden'])
    const pkg = base()
    pkg.console_theme.tokens_by_role.admin = { colorPrimary: '#000000' }
    assert.deepEqual(check(pkg), ['site_theme.admin_forbidden'])
  })
  test('applies_to 与各部分必须一致', () => {
    const user = base()
    user.applies_to = ['user']
    assert.deepEqual(check(user), ['site_theme.site_bundle_unexpected', 'site_theme.content_schema_unexpected'])
    const site = base()
    site.applies_to = ['site']
    assert.deepEqual(check(site), ['site_theme.console_theme_unexpected'])
    const none = base()
    delete none.site_bundle
    assert.deepEqual(check(none), ['site_theme.site_bundle_required'])
  })
  test('id 必须是 market.<插件 ID>', () => {
    assert.deepEqual(codes(checkContent(contentOf(EXAMPLES[0]), { pluginID: 'acme.dev.other' })), ['site_theme.id'])
    assert.deepEqual(check({ ...base(), id: 'official.site-x' }), ['site_theme.id'])
  })
  test('文件摘要、扩展名、入口', () => {
    const pkg = base()
    pkg.site_bundle.files[0].sha256 = '0'.repeat(64)
    pkg.site_bundle.files.push({ path: 'run.exe', sha256: '0'.repeat(64), data_base64: '' })
    pkg.site_bundle.entry = 'missing.html'
    assert.deepEqual(check(pkg), ['site_theme.bundle_sha256_mismatch', 'site_theme.bundle_extension', 'site_theme.bundle_entry'])
  })
  test('超过 8 MiB 拒绝', () => {
    assert.deepEqual(codes(checkContent(Buffer.alloc((8 << 20) + 1, 0x20))), ['site_theme.package_size', 'site_theme.package_json'])
  })
  test('content_schema 字段', () => {
    const pkg = base()
    pkg.content_schema = [{ key: 'Bad', type: 'text', label: { 'zh-CN': 'x' } }, { key: 'a', type: 'video', label: { 'zh-CN': 'x' } },
      { key: 'b', type: 'list', label: { 'zh-CN': 'x' }, fields: [{ key: 'c', type: 'list', label: { 'zh-CN': 'x' } }] }]
    assert.deepEqual(check(pkg), ['site_theme.content_key', 'site_theme.content_type', 'site_theme.content_nesting'])
  })
})

describe('本地预览', () => {
  const listen = async (dir) => {
    const logs = []
    const server = createPreviewServer(dir, { log: (line) => logs.push(line) })
    await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
    return { base: `http://127.0.0.1:${server.address().port}`, logs, close: () => new Promise((ok) => server.close(ok)) }
  }
  test('页面包在 /site/t/<id>/<version>/ 下，带沙箱 CSP 与 ACAO；两个公开接口可用，其他接口 403', async () => {
    const preview = await listen(EXAMPLES[0])
    try {
      const root = await fetch(`${preview.base}/`, { redirect: 'manual' })
      assert.equal(root.status, 302)
      const base = '/site/t/market.acme.dev.shield-blue/1.0.0/'
      assert.equal(root.headers.get('location'), base)
      const page = await fetch(`${preview.base}${base}`)
      assert.equal(page.status, 200)
      const csp = page.headers.get('content-security-policy')
      assert.ok(csp.startsWith('sandbox allow-scripts'))
      assert.ok(!csp.includes('allow-same-origin'), '不能给 allow-same-origin')
      assert.equal(page.headers.get('access-control-allow-origin'), '*')
      assert.equal(page.headers.get('access-control-allow-credentials'), null)
      assert.ok(SANDBOX_CSP.includes("connect-src 'self'"))
      const html = await page.text()
      assert.ok(html.includes('<script type="module" src="assets/site.js"></script>'))
      assert.ok(html.includes('href="/dashboard/login" target="_top"'))
      const module = await fetch(`${preview.base}${base}assets/defaults.mjs`, { headers: { Origin: 'null' } })
      assert.equal(module.headers.get('content-type'), 'text/javascript; charset=utf-8')
      assert.equal(module.headers.get('access-control-allow-origin'), '*')
      assert.equal((await fetch(`${preview.base}${base}assets/site.css`)).headers.get('content-type'), 'text/css; charset=utf-8')
      assert.equal((await fetch(`${preview.base}${base}x`, { method: 'POST' })).status, 405)

      const content = await fetch(`${preview.base}/v1/control-site/content`, { headers: { Origin: 'null' } })
      assert.equal(content.status, 200)
      assert.equal(content.headers.get('access-control-allow-credentials'), null)
      const doc = await content.json()
      assert.equal(doc.values, undefined)
      assert.equal(doc.auth, undefined)
      const icon = doc.plugin_content.features[0].icon.slice('asset:'.length)
      assert.equal((await fetch(`${preview.base}/v1/control-site/assets/${icon}`)).status, 200)
      assert.equal((await fetch(`${preview.base}/v1/control-site/content`, { method: 'POST', headers: { Origin: 'null' } })).status, 405)
      assert.equal((await fetch(`${preview.base}/v1/auth/me`)).status, 403)
      assert.equal((await fetch(`${preview.base}/dashboard/`)).status, 403)
      assert.ok(preview.logs.some((line) => line.includes('[违规请求]') && line.includes('/v1/auth/me')))

      // 平台登录页：沿用 /dashboard/login 等；样式经 auth_style_url（/v1/theme/auth-style）下发 {css, images}
      for (const path of ['/dashboard/login', '/dashboard/register', '/dashboard/forgot-password']) {
        assert.match(await (await fetch(`${preview.base}${path}`)).text(), /cdnca-auth-card/, path)
      }
      const style = await (await fetch(`${preview.base}/v1/theme/auth-style`)).json()
      assert.match(style.css, /cdnca-auth-card/)
      assert.match(style.images.logo, /^\/v1\/theme\/auth-style\/assets\/[0-9a-f]{64}$/)
      const logo = await fetch(`${preview.base}${style.images.logo}`)
      assert.equal(logo.headers.get('content-type'), 'image/svg+xml')
      assert.match(await (await fetch(`${preview.base}/dashboard/login`)).text(),
        /--cdnca-auth-image-logo: url\("\/v1\/theme\/auth-style\/assets\/[0-9a-f]{64}"\)/)
      assert.ok(preview.logs.includes('[预检] 通过'))
    } finally {
      await preview.close()
    }
  })

  test('包内 woff2 字体与模块脚本按原类型、带 ACAO 提供', async () => {
    const dir = join(temp, 'preview-font')
    scaffold(dir, { template: 'site', pluginID: 'acme.dev.font' })
    writeFileSync(join(dir, 'site/assets/font.woff2'), Buffer.concat([Buffer.from('wOF2'), Buffer.alloc(60)]))
    writeFileSync(join(dir, 'site/assets/extra.mjs'), 'export const x = 1\n')
    const preview = await listen(dir)
    try {
      const base = '/site/t/market.acme.dev.font/1.0.0/'
      const font = await fetch(`${preview.base}${base}assets/font.woff2`, { headers: { Origin: 'null' } })
      assert.equal(font.status, 200)
      assert.equal(font.headers.get('content-type'), 'font/woff2')
      assert.equal(font.headers.get('access-control-allow-origin'), '*')
      const mod = await fetch(`${preview.base}${base}assets/extra.mjs`, { headers: { Origin: 'null' } })
      assert.equal(mod.headers.get('content-type'), 'text/javascript; charset=utf-8')
      assert.deepEqual(checkContent(contentOf(dir)).items, [])
    } finally {
      await preview.close()
    }
  })
})
