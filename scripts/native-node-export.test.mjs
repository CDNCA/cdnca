import test from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { copyRuntimeTree, runtimeELF, exportNativeRuntime } from './native-node-export.mjs'

test('materializes image-internal relative and absolute links without retaining links', (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-runtime-copy-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  fs.mkdirSync(path.join(root, 'image/lib'), { recursive: true })
  fs.writeFileSync(path.join(root, 'image/lib/real.so'), 'library', { mode: 0o755 })
  fs.writeFileSync(path.join(root, 'image/lib/real.so.old'), 'superseded library', { mode: 0o755 })
  fs.symlinkSync('/lib/real.so', path.join(root, 'image/lib/absolute.so'))
  fs.symlinkSync('real.so', path.join(root, 'image/lib/relative.so'))
  copyRuntimeTree(path.join(root, 'image'), 'lib', path.join(root, 'output'))
  for (const name of ['real.so', 'absolute.so', 'relative.so']) {
    assert.equal(fs.readFileSync(path.join(root, 'output', name), 'utf8'), 'library')
    assert.equal(fs.lstatSync(path.join(root, 'output', name)).isSymbolicLink(), false)
    assert.equal(fs.statSync(path.join(root, 'output', name)).mode & 0o777, 0o555)
  }
  assert.equal(fs.existsSync(path.join(root, 'output/real.so.old')), false)
})

test('rejects links escaping an image, cycles and existing output', (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-runtime-reject-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  fs.mkdirSync(path.join(root, 'image'))
  fs.symlinkSync('../outside', path.join(root, 'image/escape'))
  assert.throws(() => copyRuntimeTree(path.join(root, 'image'), 'escape', path.join(root, 'out')), /escapes/)
  fs.symlinkSync('cycle', path.join(root, 'image/cycle'))
  assert.throws(() => copyRuntimeTree(path.join(root, 'image'), 'cycle', path.join(root, 'out')), /symlink/)
  assert.throws(() => exportNativeRuntime(path.join(root, 'image'), root), /unsafe/)
})

test('ELF validation rejects malformed, wrong-architecture and non-executable objects', () => {
  assert.equal(runtimeELF(Buffer.from('Lua source')), null)
  assert.throws(() => runtimeELF(Buffer.from('7f454c46', 'hex')), /ELF/)
  const elf = Buffer.alloc(120)
  Buffer.from('7f454c46', 'hex').copy(elf)
  elf[4] = 2; elf[5] = 1; elf.writeUInt16LE(3, 16); elf.writeUInt16LE(62, 18)
  elf.writeBigUInt64LE(64n, 32); elf.writeUInt16LE(56, 54); elf.writeUInt16LE(1, 56); elf.writeUInt32LE(3, 64)
  assert.deepEqual(runtimeELF(elf), { interpreter: true, dynamic: false })
  elf.writeUInt16LE(183, 18)
  assert.throws(() => runtimeELF(elf), /x86-64/)
  elf.writeUInt16LE(62, 18); elf.writeUInt16LE(2, 56)
  assert.throws(() => runtimeELF(elf), /headers/)
})

// A static x86-64 executable (no PT_INTERP, no PT_DYNAMIC), like CGO_ENABLED=0 Go.
export function staticELF(extra = Buffer.alloc(0)) {
  const elf = Buffer.alloc(120)
  Buffer.from('7f454c46', 'hex').copy(elf)
  elf[4] = 2; elf[5] = 1; elf.writeUInt16LE(2, 16); elf.writeUInt16LE(62, 18)
  elf.writeBigUInt64LE(64n, 32); elf.writeUInt16LE(56, 54); elf.writeUInt16LE(1, 56); elf.writeUInt32LE(1, 64)
  return Buffer.concat([elf, extra])
}

function exportFixture(t, h3probe) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-runtime-export-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const image = path.join(root, 'image')
  const put = (name, bytes, mode = 0o644) => { fs.mkdirSync(path.dirname(path.join(image, name)), { recursive: true }); fs.writeFileSync(path.join(image, name), bytes, { mode }) }
  for (const name of ['nginx/sbin/nginx', 'bin/openresty']) put(`usr/local/openresty/${name}`, 'openresty fixture\n', 0o755)
  for (const name of ['nginx/modules/.keep', 'nginx/conf/nginx.conf', 'lualib/x.lua', 'luajit/lib/.keep', 'openssl3/lib/.keep', 'pcre2/lib/.keep']) put(`usr/local/openresty/${name}`, 'x\n')
  put('lib/ld-musl-x86_64.so.1', 'loader fixture\n', 0o755)
  put('usr/lib/.keep', '')
  put('usr/local/share/cdnca/x.lua', '-- x\n'); put('opt/cdnca/l4geo/x.lua', '-- x\n')
  if (h3probe) put('usr/local/bin/h3probe', h3probe, 0o755)
  return { image, output: path.join(root, 'payload') }
}

test('exports the static h3probe as runtime/bin/h3probe without patchelf', (t) => {
  const f = exportFixture(t, staticELF(Buffer.from('h3probe fixture')))
  const exported = exportNativeRuntime(f.image, f.output)
  const entry = exported.files.find((file) => file.path === 'runtime/bin/h3probe')
  assert.ok(entry, 'h3probe missing from the export')
  assert.equal(fs.statSync(path.join(f.output, 'runtime/bin/h3probe')).mode & 0o777, 0o555)
  assert.deepEqual(fs.readFileSync(path.join(f.output, 'runtime/bin/h3probe')), staticELF(Buffer.from('h3probe fixture')))
})

test('export refuses a runtime without a static h3probe', (t) => {
  assert.throws(() => exportNativeRuntime(exportFixture(t).image, exportFixture(t).output), /h3probe/)
  const dynamic = staticELF(); dynamic.writeUInt32LE(2, 64)
  const f = exportFixture(t, dynamic)
  assert.throws(() => exportNativeRuntime(f.image, f.output), /h3probe.*static/)
})
