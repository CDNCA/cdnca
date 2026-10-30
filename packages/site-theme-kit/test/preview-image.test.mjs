// node --test packages/site-theme-kit/test/ — 主题卡片预览图（preview）
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, describe, test } from 'node:test'

import { buildContent, pack } from '../lib/pack.mjs'
import { checkContent, checkPreview, PREVIEW_MAX_BYTES } from '../lib/rules.mjs'
import { scaffold } from '../lib/scaffold.mjs'

const repo = resolve(import.meta.dirname, '../../..')
const EXAMPLES = ['shield-blue', 'honey-orange'].map((name) => join(repo, 'examples/site-themes', name))
const temp = mkdtempSync(join(tmpdir(), 'site-theme-preview-'))
after(() => rmSync(temp, { recursive: true, force: true }))
const codes = (findings) => findings.items.map((item) => item.code)
const contentOf = (dir) => Buffer.from(`${JSON.stringify(buildContent(dir).content)}\n`)
const webp = Buffer.concat([Buffer.from('RIFF\0\0\0\0WEBPVP8 '), Buffer.alloc(16)])

describe('预览图', () => {
  test('示例主题带上 preview.webp，打包进 content', () => {
    for (const dir of EXAMPLES) {
      const built = buildContent(dir)
      assert.ok(built.previewPath?.endsWith('preview.webp'), dir)
      assert.ok(Buffer.from(built.content.preview, 'base64').length <= PREVIEW_MAX_BYTES)
      assert.deepEqual(codes(checkContent(contentOf(dir))), [])
    }
  })

  test('格式与上限按内容校验', () => {
    assert.equal(checkPreview(webp.toString('base64')), '')
    assert.equal(checkPreview(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString('base64')), 'preview')
    assert.equal(checkPreview('not base64!'), 'preview')
    assert.equal(checkPreview(''), 'preview')
    assert.equal(checkPreview(Buffer.concat([webp, Buffer.alloc(PREVIEW_MAX_BYTES)]).toString('base64')), 'preview_size')
    const pkg = JSON.parse(contentOf(EXAMPLES[0]))
    pkg.preview = 'AAAA'
    assert.ok(codes(checkContent(Buffer.from(JSON.stringify(pkg)))).includes('site_theme.preview'))
    pkg.preview = webp.toString('base64')
    pkg.auth_style = { ...(pkg.auth_style ?? { css: '' }), images: { preview: webp.toString('base64') } }
    assert.ok(codes(checkContent(Buffer.from(JSON.stringify(pkg)))).includes('site_theme.image_slot'))
  })

  test('没有预览图时只提示，不报错', () => {
    const dir = join(temp, 'plain')
    scaffold(dir, { template: 'site', pluginID: 'acme.dev.plain' })
    const out = pack(dir, { outDir: join(temp, 'plain-dist') })
    assert.deepEqual(out.findings, [])
    assert.equal(out.previewPath, null)
    assert.ok(out.notices.some((notice) => notice.includes('建议提供预览图')))
    writeFileSync(join(dir, 'preview.webp'), webp)
    const withPreview = pack(dir, { outDir: join(temp, 'plain-dist2') })
    assert.deepEqual(withPreview.notices, [])
    assert.equal(JSON.parse(readFileSync(withPreview.contentPath, 'utf8')).preview, webp.toString('base64'))
  })
})
