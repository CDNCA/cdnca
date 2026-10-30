// 用平台自己的校验库复核：脚手架三种模板与两个示例打包后的 content 必须通过
// libs/sitetheme.Parse（第三方）与 libs/themepack.Render（console_theme）；
// 本地预检（lib/rules.mjs）对一组违规样本给出的错误码必须与库一致。
// 需要 Go 工具链；没有 go 时跳过（CI 的 go-libs 一项另有库自身测试）。
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { buildContent, pack } from '../lib/pack.mjs'
import { checkContent } from '../lib/rules.mjs'
import { scaffold, TEMPLATES } from '../lib/scaffold.mjs'

const repo = resolve(import.meta.dirname, '../../..')
const temp = mkdtempSync(join(tmpdir(), 'site-theme-go-'))
const binary = join(temp, 'sitetheme-check')
const hasGo = spawnSync('go', ['version']).status === 0
after(() => rmSync(temp, { recursive: true, force: true }))

function libCheck(files) {
  const run = spawnSync(binary, files, { encoding: 'utf8' })
  return run.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
}

describe('libs/sitetheme 复核', { skip: !hasGo && 'go not installed' }, () => {
  before(() => {
    execFileSync('go', ['-C', join(repo, 'packages/site-theme-kit/sitetheme-check'), 'build', '-o', binary, '.'],
      { env: { ...process.env, GOWORK: 'off', GOFLAGS: '-mod=mod' }, stdio: 'inherit' })
  })

  test('脚手架三种模板与两个示例都通过库校验', () => {
    const files = []
    for (const template of TEMPLATES) {
      const dir = join(temp, `t-${template.replace('+', '-')}`)
      scaffold(dir, { template, pluginID: 'acme.dev.ocean' })
      files.push(pack(dir).contentPath)
    }
    for (const name of ['shield-blue', 'honey-orange']) {
      files.push(pack(join(repo, 'examples/site-themes', name), { outDir: join(temp, name) }).contentPath)
    }
    const results = libCheck(files)
    assert.equal(results.length, files.length)
    for (const r of results) assert.ok(r.ok, `${r.file}: ${r.code} ${r.field}`)
    assert.deepEqual(results.map((r) => r.applies_to), [['user', 'site'], ['user'], ['site'], ['user', 'site'], ['user', 'site']])
  })

  test('违规样本：本地预检与库给出相同错误码', () => {
    const base = buildContent(join(repo, 'examples/site-themes/shield-blue')).content
    const file = (name, text) => ({ path: name, sha256: '', data_base64: Buffer.from(text).toString('base64') })
    const withFile = (name, text) => {
      const pkg = structuredClone(base)
      const extra = file(name, text)
      extra.sha256 = createHash('sha256').update(text).digest('hex')
      pkg.site_bundle.files.push(extra)
      return pkg
    }
    const samples = {
      admin_scope: { ...structuredClone(base), applies_to: ['admin', 'user', 'site'] },
      dashboard: withFile('x.js', 'location.href="/dashboard/"'),
      dashboard_other: withFile('x.html', '<a href="/dashboard/login-admin">x</a>'),
      api: withFile('x.js', 'fetch("/v1/auth/me")'),
      sw: withFile('x.js', 'navigator.serviceWorker.register("s.js")'),
      base_tag: withFile('x.html', '<base href="/">'),
      external: withFile('x.html', '<script src="https://cdn.example.com/a.js"></script>'),
      extension: withFile('x.exe', 'MZ'),
      user_only_bundle: { ...structuredClone(base), applies_to: ['user'] },
      site_only_console: { ...structuredClone(base), applies_to: ['site'] },
      auth_import: { ...structuredClone(base), auth_style: { css: '@import "a.css";' } },
      auth_url: { ...structuredClone(base), auth_style: { css: '.a{background:url(https://cdn.example.com/a.png)}' } },
      content_type: { ...structuredClone(base), content_schema: [{ key: 'a', type: 'video', label: { 'zh-CN': 'x' } }] },
    }
    const admin = structuredClone(base)
    admin.console_theme.tokens_by_role.admin = { colorPrimary: '#000000' }
    samples.admin_tokens = admin
    const paths = Object.entries(samples).map(([name, pkg]) => {
      const path = join(temp, `sample-${name}.json`)
      writeFileSync(path, JSON.stringify(pkg))
      return path
    })
    const results = libCheck(paths)
    for (const [index, name] of Object.keys(samples).entries()) {
      const lib = results[index]
      assert.equal(lib.ok, false, `${name} should fail in libs/sitetheme`)
      const local = checkContent(Buffer.from(JSON.stringify(samples[name]))).items
      assert.ok(local.length > 0, `${name} should fail locally`)
      assert.equal(local[0].code, lib.code, `${name}: local ${local[0].code} vs lib ${lib.code}`)
    }
  })
})
