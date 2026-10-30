// node --test packages/site-theme-kit/test/
// 入口判断：经别名/软链、含空格或需 URL 编码的路径、无扩展名 bin 调用时都必须真正执行 main
// （断言实际产物，而不是只看退出码 0）；被 import 时不执行。
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { after, describe, test } from 'node:test'

import { isEntrypoint } from '../bin/cdnca-site-theme.mjs'

const kit = resolve(import.meta.dirname, '..')
const bin = join(kit, 'bin/cdnca-site-theme.mjs')
const temp = mkdtempSync(join(tmpdir(), 'site-theme-entry-'))
after(() => rmSync(temp, { recursive: true, force: true }))

// 假签名器：按 cdnca-plugin sign-manifest 的参数写出带 integrity 的 manifest.signed.json。
const signer = join(temp, 'fake-cdnca-plugin.mjs')
writeFileSync(signer, `#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
const a = process.argv.slice(2)
if (a[0] !== 'sign-manifest') process.exit(2)
const get = (f) => a[a.indexOf(f) + 1]
const m = JSON.parse(readFileSync(get('-in'), 'utf8'))
m.integrity = { algorithm: 'Ed25519', key_id: 'test', payload_sha256: 'test', signature: 'test' }
writeFileSync(get('-out'), JSON.stringify(m))
`)
chmodSync(signer, 0o755)
const key = join(temp, 'publisher.key')
writeFileSync(key, 'test-key\n', { mode: 0o600 })

/** 用给定的脚本路径跑 init + pack --sign，返回进程结果与工程目录。 */
function initAndPack(script, project) {
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' })
  const init = run('init', project, '--template', 'user+site', '--plugin-id', 'acme.dev.ocean', '--name', '海蓝')
  const packed = run('pack', project, '--version', '1.2.3', '--sign', '--key', key, '--cdnca-plugin', signer)
  return { init, packed }
}

function assertProduced(project, { init, packed }) {
  assert.equal(init.status, 0, init.stderr)
  assert.match(init.stdout, /已生成 user\+site 模板/)
  assert.ok(existsSync(join(project, 'plugin.manifest.json')), 'init 必须生成工程文件')
  assert.equal(packed.status, 0, packed.stderr)
  assert.match(packed.stdout, /signed {4}/)
  const content = JSON.parse(readFileSync(join(project, 'dist/theme.json'), 'utf8'))
  assert.equal(content.id, 'market.acme.dev.ocean')
  assert.ok(existsSync(join(project, 'dist/schemas/config.schema.json')))
  const signed = JSON.parse(readFileSync(join(project, 'dist/manifest.signed.json'), 'utf8'))
  assert.equal(signed.metadata.id, 'acme.dev.ocean')
  assert.equal(signed.metadata.version, '1.2.3')
  assert.equal(signed.integrity.algorithm, 'Ed25519')
}

describe('入口判断', () => {
  test('物理绝对路径', () => {
    const project = join(temp, 'physical')
    assertProduced(project, initAndPack(realpathSync(bin), project))
  })

  test('目录软链（与 macOS /var → /private/var 同类）', () => {
    const link = join(temp, 'kit-link')
    symlinkSync(kit, link)
    const project = join(temp, 'via-link')
    assertProduced(project, initAndPack(join(link, 'bin/cdnca-site-theme.mjs'), project))
  })

  test('系统目录别名 /var（仅在 /var 是软链的系统上）', { skip: !(existsSync('/var') && lstatSync('/var').isSymbolicLink()) }, () => {
    const base = mkdtempSync('/var/tmp/site-theme-entry-')
    try {
      assert.notEqual(realpathSync(base), base)
      const link = join(base, 'kit')
      symlinkSync(kit, link)
      const project = join(base, 'project')
      assertProduced(project, initAndPack(join(link, 'bin/cdnca-site-theme.mjs'), project))
    } finally {
      rmSync(base, { recursive: true, force: true })
    }
  })

  test('路径含空格、百分号、井号与中文（file URL 会被编码）', () => {
    // 复制而非软链：真实文件路径本身就需要编码，import.meta.url 与 argv[1] 字面不同。
    const dir = join(temp, 'my kit %20 #1 主题')
    for (const part of ['bin', 'lib', 'package.json']) cpSync(join(kit, part), join(dir, 'kit', part), { recursive: true })
    const script = join(dir, 'kit/bin/cdnca-site-theme.mjs')
    assert.notEqual(pathToFileURL(realpathSync(script)).href, `file://${realpathSync(script)}`, '用例必须覆盖 URL 编码')
    const project = join(dir, 'project')
    assertProduced(project, initAndPack(script, project))
  })

  test('无扩展名的 bin 软链（包管理器安装的形式）', () => {
    const dir = join(temp, 'node_modules/.bin')
    mkdirSync(dir, { recursive: true })
    symlinkSync(bin, join(dir, 'cdnca-site-theme'))
    const project = join(temp, 'via-bin')
    assertProduced(project, initAndPack(join(dir, 'cdnca-site-theme'), project))
  })

  test('被 import 时不执行 main', () => {
    const importer = join(temp, 'importer.mjs')
    writeFileSync(importer, `const m = await import(${JSON.stringify(pathToFileURL(bin).href)})\nconsole.log(typeof m.main)\n`)
    const r = spawnSync(process.execPath, [importer], { encoding: 'utf8' })
    assert.equal(r.status, 0, r.stderr)
    assert.equal(r.stdout, 'function\n')
    assert.equal(r.stderr, '', 'main 若被执行会打印用法')
  })

  test('用法错误与未知命令保持退出码 2', () => {
    const r = spawnSync(process.execPath, [bin, 'nope'], { encoding: 'utf8' })
    assert.equal(r.status, 2)
    assert.match(r.stderr, /用法/)
  })

  test('isEntrypoint：其他文件、缺参数、不存在的路径都返回 false', () => {
    const url = pathToFileURL(bin).href
    assert.equal(isEntrypoint(url, bin), true)
    assert.equal(isEntrypoint(url, undefined), false)
    assert.equal(isEntrypoint(url, join(kit, 'lib/pack.mjs')), false)
    assert.equal(isEntrypoint(url, join(temp, 'missing.mjs')), false)
  })
})
