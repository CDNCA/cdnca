import test, { after, before } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { luaSources, goBuildInfo } from './native-node-runtime-acceptance.mjs'

const repository = path.resolve(import.meta.dirname, '..')
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex')
const checks = ['native_loader', 'dynamic_modules', 'http1', 'http2', 'http3', 'stream_tcp', 'lua', 'same_master_reload', 'new_worker', 'http3_after_reload']
const acceptanceChecks = ['source_signature', 'patches', 'build_inputs', 'configure', 'native_loader', 'h3probe', 'http1', 'http2', 'http3', 'stream', 'lua', 'reload']
const runtimeMembers = ['runtime/openresty/bin/openresty', 'runtime/openresty/nginx/sbin/nginx', 'runtime/lib/ld-musl-x86_64.so.1', 'runtime/openresty/nginx/modules/ngx_http_geoip_module.so']
// Native Dockerfile build-context files (container path -> repository path); patches are added per file.
const contract = {
  '/source-contract/verify-sources.mjs': 'edge/openresty/native/verify-sources.mjs',
  '/source-contract/sources.lock.json': 'edge/openresty/native/sources.lock.json',
  '/source-contract/build-openresty.sh': 'edge/openresty/native/build-openresty.sh',
  // resty.ipmatcher (firewall action engine), vendored at the container image's pin.
  '/source-contract/vendor/ipmatcher.lua': 'edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua',
  '/native-node-export.mjs': 'scripts/native-node-export.mjs',
  '/h3probe-src/go.mod': 'edge/openresty/http3/client/client.mod',
  '/h3probe-src/go.sum': 'edge/openresty/http3/client/client.sum',
  '/h3probe-src/main.go': 'edge/openresty/http3/client/main.go',
}
const committedInputs = ['edge/openresty/native/Dockerfile', 'edge/openresty/native/verify-sources.mjs', 'edge/openresty/native/build-openresty.sh',
  'edge/openresty/native/sources.lock.json', 'scripts/native-node-export.mjs', 'scripts/native-node-runtime-smoke.sh', 'edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua',
  'edge/openresty/http3/client/client.mod', 'edge/openresty/http3/client/client.sum', 'edge/openresty/http3/client/main.go']
let sourceFixture

before(() => {
  // GPG's Unix socket must fit macOS' short sockaddr_un path limit.
  const directory = fs.realpathSync(fs.mkdtempSync('/tmp/cdnca-acceptance-source-test-'))
  sourceFixture = { directory, home: path.join(directory, 'gnupg') }
  fs.mkdirSync(sourceFixture.home, { mode: 0o700 })
  const gpg = (...args) => execFileSync('gpg', ['--homedir', sourceFixture.home, '--batch', '--no-tty', ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
  gpg('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'Runtime acceptance fixture <runtime-acceptance@invalid>', 'ed25519', 'sign', '0')
  sourceFixture.fingerprint = gpg('--with-colons', '--list-keys').toString().split('\n').find((line) => line.startsWith('fpr:')).split(':')[9]
  sourceFixture.publicKey = gpg('--armor', '--export', sourceFixture.fingerprint)
  const prefix = 'openresty-1.31.1.1', source = path.join(directory, prefix, 'bundle/nginx-1.31.1')
  fs.mkdirSync(source, { recursive: true })
  fs.writeFileSync(path.join(source, 'example.c'), 'before\n')
  sourceFixture.archive = path.join(directory, 'source.tar.gz')
  execFileSync('tar', ['-czf', sourceFixture.archive, '-C', directory, prefix])
  gpg('--pinentry-mode', 'loopback', '--passphrase', '', '--armor', '--detach-sign', '--output', `${sourceFixture.archive}.asc`, sourceFixture.archive)
  sourceFixture.signature = fs.readFileSync(`${sourceFixture.archive}.asc`)
  sourceFixture.patch = Buffer.from('--- a/example.c\n+++ b/example.c\n@@ -1 +1 @@\n-before\n+after\n')
  sourceFixture.lock = {
    schema: 'cdnca.native-openresty.sources/v1',
    source: { version: '1.31.1.1', nginx_core: '1.31.1', archive_prefix: prefix, sha256: hash(fs.readFileSync(sourceFixture.archive)),
      signature: { file: 'patches/test-source.asc', sha256: hash(sourceFixture.signature) },
      signer: { file: 'patches/test-public.asc', sha256: hash(sourceFixture.publicKey), fingerprint: sourceFixture.fingerprint } },
    build_base: { reference: `openresty/openresty@sha256:${'e'.repeat(64)}`, openssl: '3.5.8' },
    patches: [{ file: 'patches/test.patch', directory: 'bundle/nginx-1.31.1', sha256: hash(sourceFixture.patch),
      files: [{ path: 'example.c', before: hash('before\n'), after: hash('after\n') }] }],
  }
})
after(() => {
  if (!sourceFixture) return
  execFileSync('gpgconf', ['--homedir', sourceFixture.home, '--kill', 'all'], { stdio: 'pipe' })
  fs.rmSync(sourceFixture.directory, { recursive: true, force: true })
})

const nginxV = (version = '1.31.1.1', openssl = '3.5.8', configure = '--with-http_ssl_module --with-http_v2_module --with-http_v3_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module --with-stream_realip_module --with-compat --with-threads --add-module=/tmp/openresty-source/bundle/cdnca-ja4 --add-module=/tmp/openresty-source/bundle/ngx_brotli') =>
  `nginx version: openresty/${version}\nbuilt with OpenSSL ${openssl} 1 Jul 2025\nTLS SNI support enabled\nconfigure arguments: --prefix=/usr/local/openresty/nginx --add-module=../ngx_devel_kit-0.3.4 ${configure}\n`

// Replace a possibly read-only file, as the exporter's immutable 0444/0555 modes require.
function put(filename, bytes, mode = 0o444) {
  fs.mkdirSync(path.dirname(filename), { recursive: true })
  if (fs.existsSync(filename)) fs.chmodSync(filename, 0o644)
  fs.writeFileSync(filename, bytes)
  fs.chmodSync(filename, mode)
}

// Dependencies linked into h3probe, as `go version -m` lists them (client.sum hashes).
function h3probeDeps(repo) {
  const sums = new Map(fs.readFileSync(path.join(repo, 'edge/openresty/http3/client/client.sum'), 'utf8').split('\n')
    .filter((line) => line && !line.includes('/go.mod ')).map((line) => { const [module, version, sum] = line.split(' '); return [module, { version, sum }] }))
  return ['github.com/quic-go/qpack', 'github.com/quic-go/quic-go', 'golang.org/x/crypto', 'golang.org/x/net', 'golang.org/x/sys', 'golang.org/x/text']
    .map((module) => ({ path: module, ...sums.get(module) }))
}

const goVarString = (text) => {
  const bytes = Buffer.from(text), prefix = []
  for (let length = bytes.length; ; length >>= 7) { if (length < 0x80) { prefix.push(length); break } prefix.push((length & 0x7f) | 0x80) }
  return Buffer.concat([Buffer.from(prefix), bytes])
}

// A static linux/amd64 ELF whose .go.buildinfo section is what Go 1.18+ writes
// (inline strings, flags 0x2): the bytes goBuildInfo() reads from h3probe.
function goBuildInfoELF({ go = 'go1.27.3', module = 'github.com/cdnca/cdnca/edge/openresty/http3/client', deps, settings, dynamic = false } = {}) {
  settings ??= { '-buildmode': 'exe', '-compiler': 'gc', '-trimpath': 'true', CGO_ENABLED: '0', GOARCH: 'amd64', GOOS: 'linux', GOAMD64: 'v1' }
  const lines = [`path\t${module}`, `mod\t${module}\t(devel)\t`, ...deps.map((dep) => `dep\t${dep.path}\t${dep.version}\t${dep.sum}`),
    ...Object.entries(settings).map(([key, value]) => `build\t${key}=${value}`)]
  const sentinel = Buffer.alloc(16)
  const modinfo = Buffer.concat([sentinel, Buffer.from(lines.join('\n') + '\n'), sentinel])
  const header = Buffer.alloc(32); Buffer.from('\xff Go buildinf:', 'latin1').copy(header); header[14] = 8; header[15] = 2
  const section = Buffer.concat([header, goVarString(go), goVarString(modinfo.toString('latin1'))])
  const names = Buffer.from('\0.go.buildinfo\0.shstrtab\0')
  const sectionOffset = 0x100, namesOffset = sectionOffset + section.length, headersOffset = (namesOffset + names.length + 7) & ~7
  const elf = Buffer.alloc(headersOffset + 3 * 64)
  Buffer.from('7f454c46', 'hex').copy(elf); elf[4] = 2; elf[5] = 1; elf[6] = 1
  elf.writeUInt16LE(2, 16); elf.writeUInt16LE(62, 18)
  elf.writeBigUInt64LE(64n, 32); elf.writeBigUInt64LE(BigInt(headersOffset), 40)
  elf.writeUInt16LE(56, 54); elf.writeUInt16LE(1, 56); elf.writeUInt16LE(64, 58); elf.writeUInt16LE(3, 60); elf.writeUInt16LE(2, 62)
  elf.writeUInt32LE(dynamic ? 2 : 1, 64)
  section.copy(elf, sectionOffset); names.copy(elf, namesOffset)
  const sectionHeader = (index, name, type, offset, size) => {
    const at = headersOffset + index * 64
    elf.writeUInt32LE(name, at); elf.writeUInt32LE(type, at + 4); elf.writeBigUInt64LE(BigInt(offset), at + 24); elf.writeBigUInt64LE(BigInt(size), at + 32)
  }
  sectionHeader(1, 1, 1, sectionOffset, section.length)
  sectionHeader(2, 15, 3, namesOffset, names.length)
  return elf
}

// The build context the native Dockerfile copies, as the exporter records it with sha256sum.
function recordedBuildInputs(f) {
  const entries = Object.entries(contract).map(([target, member]) => [target, fs.readFileSync(path.join(f.repo, member))])
  const patches = path.join(f.repo, 'edge/openresty/native/patches')
  for (const name of fs.readdirSync(patches)) entries.push([`/source-contract/patches/${name}`, fs.readFileSync(path.join(patches, name))])
  return entries.sort(([a], [b]) => a < b ? -1 : 1).map(([target, bytes]) => `${hash(bytes)}  ${target}\n`).join('')
}

function runtimeInventory(f) {
  const files = []
  const walk = (relative) => {
    for (const name of fs.readdirSync(path.join(f.payload, relative)).sort()) {
      const member = `${relative}/${name}`
      if (fs.lstatSync(path.join(f.payload, member)).isDirectory()) walk(member)
      else files.push({ path: member, sha256: hash(fs.readFileSync(path.join(f.payload, member))) })
    }
  }
  walk('runtime'); walk('lua')
  return files.sort((a, b) => a.path < b.path ? -1 : 1)
}

// Recompute export and smoke inventories after the payload changed, as a rebuild would.
function nativeRuntimeAcceptanceResync(f) {
  const files = runtimeInventory(f)
  put(path.join(f.payload, 'evidence/runtime-export.json'), JSON.stringify({ schema: 'cdnca.native-node.runtime-export/v1', interpreter: '/opt/cdnca-node/current/runtime/lib/ld-musl-x86_64.so.1', files }))
  f.smokeDocument.files = files
  fs.writeFileSync(f.smoke, JSON.stringify(f.smokeDocument))
}

// A fresh build of the candidate commit: what the native Dockerfile exporter produces.
function nativeRuntimeAcceptanceBuild(f) {
  fs.rmSync(f.payload, { recursive: true, force: true })
  for (const member of runtimeMembers) put(path.join(f.payload, member), member.endsWith('/nginx') || member.endsWith('/openresty') ? 'openresty fixture only\n' : `${member} fixture only\n`, 0o555)
  put(path.join(f.payload, 'runtime/bin/h3probe'), goBuildInfoELF({ deps: h3probeDeps(f.repo), ...f.h3probe }), 0o555)
  for (const [member, source] of Object.entries(luaSources)) put(path.join(f.payload, member), fs.readFileSync(path.join(f.repo, source)))
  const lock = fs.readFileSync(path.join(f.repo, 'edge/openresty/native/sources.lock.json')), parsed = JSON.parse(lock)
  const evidence = (name, bytes) => put(path.join(f.payload, 'evidence', name), bytes)
  evidence('runtime-sources.lock.json', lock)
  evidence('source-verification.json', JSON.stringify({ source_sha256: parsed.source.sha256, signer: parsed.source.signer.fingerprint, patches: parsed.patches.length, output: '/tmp/openresty-source', evidence: 'source-only' }))
  evidence('runtime-build-inputs.sha256', recordedBuildInputs(f))
  evidence('openresty-V.txt', nginxV())
  evidence('runtime-apk-inventory.txt', 'P:musl\nV:1.2.5-r10\n')
  f.smokeDocument = { schema: 'cdnca.native-node.runtime-smoke/v1', status: 'PASS', source: { commit: f.commit, tree: f.tree }, checks: Object.fromEntries(checks.map((key) => [key, 'PASS'])), files: [] }
  nativeRuntimeAcceptanceResync(f)
}

function nativeRuntimeAcceptanceFixture(t, sourceMutation = () => {}) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-acceptance-test-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const f = { root, repo: path.join(root, 'repo'), payload: path.join(root, 'payload'), smoke: path.join(root, 'smoke.json'), archive: path.join(root, 'source.tar.gz') }
  fs.mkdirSync(f.repo)
  for (const member of ['edge/openresty', 'scripts/native-node-runtime-acceptance.mjs', 'scripts/native-node-package.mjs', 'scripts/native-node-export.mjs', 'scripts/native-node-runtime-smoke.sh']) {
    fs.mkdirSync(path.dirname(path.join(f.repo, member)), { recursive: true })
    fs.cpSync(path.join(repository, member), path.join(f.repo, member), { recursive: true })
  }
  const lock = structuredClone(sourceFixture.lock)
  sourceMutation(lock)
  const native = path.join(f.repo, 'edge/openresty/native')
  fs.writeFileSync(path.join(native, 'sources.lock.json'), JSON.stringify(lock))
  fs.writeFileSync(path.join(native, 'patches/test-source.asc'), sourceFixture.signature)
  fs.writeFileSync(path.join(native, 'patches/test-public.asc'), sourceFixture.publicKey)
  fs.writeFileSync(path.join(native, 'patches/test.patch'), sourceFixture.patch)
  fs.copyFileSync(sourceFixture.archive, f.archive)
  const git = (...args) => execFileSync('git', args, { cwd: f.repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '--quiet'); git('config', 'user.name', 'Acceptance fixture'); git('config', 'user.email', 'acceptance@invalid')
  git('add', 'edge/openresty', 'scripts')
  git('commit', '--quiet', '-m', 'fixture candidate')
  f.commit = git('rev-parse', 'HEAD'); f.tree = git('rev-parse', 'HEAD^{tree}')
  f.git = git
  nativeRuntimeAcceptanceBuild(f)
  f.output = path.join(f.payload, 'evidence/runtime-acceptance.json')
  return f
}

function nativeRuntimeAcceptanceCommit(f, member, text) {
  fs.appendFileSync(path.join(f.repo, member), text)
  f.git('add', member); f.git('commit', '--quiet', '-m', `changed ${member}`)
  f.commit = f.git('rev-parse', 'HEAD'); f.tree = f.git('rev-parse', 'HEAD^{tree}')
  f.smokeDocument.source = { commit: f.commit, tree: f.tree }
  fs.writeFileSync(f.smoke, JSON.stringify(f.smokeDocument))
}

function nativeRuntimeAcceptanceRun(f, extra = [], nodeArguments = []) {
  return spawnSync(process.execPath, [...nodeArguments, path.join(f.repo, 'scripts/native-node-runtime-acceptance.mjs'),
    '--source-commit', f.commit, '--payload-dir', f.payload, '--smoke-result', f.smoke, '--source-archive', f.archive, ...extra], { encoding: 'utf8' })
}
test('accepts a fresh native build whose runtime inputs changed, without any signed baseline', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t)
  // Patches 18–22 changed the build inputs; a rebuild of this commit is accepted on its own evidence.
  nativeRuntimeAcceptanceCommit(f, 'edge/openresty/native/build-openresty.sh', '\n# rebuilt recipe\n')
  nativeRuntimeAcceptanceCommit(f, 'edge/openresty/range/guard.lua', '\n-- rebuilt\n')
  nativeRuntimeAcceptanceBuild(f)
  const result = nativeRuntimeAcceptanceRun(f)
  assert.equal(result.status, 0, result.stderr)
  const acceptance = JSON.parse(fs.readFileSync(f.output))
  const lockBytes = fs.readFileSync(path.join(f.repo, 'edge/openresty/native/sources.lock.json')), lock = JSON.parse(lockBytes)
  assert.equal(acceptance.schema, 'cdnca.native-node.runtime-acceptance/v1')
  assert.equal(acceptance.mode, 'fresh-build')
  assert.deepEqual(acceptance.source, { commit: f.commit, tree: f.tree })
  assert.deepEqual(acceptance.runtime, { openresty_version: '1.31.1.1', nginx_version: '1.31.1', source_sha256: lock.source.sha256,
    patch_manifest_sha256: hash(lockBytes), release_eligible: true })
  assert.deepEqual(acceptance.files, f.smokeDocument.files)
  const patches = fs.readdirSync(path.join(f.repo, 'edge/openresty/native/patches')).map((name) => `edge/openresty/native/patches/${name}`)
  assert.deepEqual(acceptance.build.inputs, [...committedInputs, ...patches].sort().map((member) => ({ path: member, sha256: hash(fs.readFileSync(path.join(f.repo, member))) })))
  assert.equal(acceptance.build.script_sha256, hash(fs.readFileSync(path.join(f.repo, 'edge/openresty/native/build-openresty.sh'))))
  assert.deepEqual(acceptance.build.patches, lock.patches.map((patch) => ({ file: patch.file, sha256: patch.sha256 })))
  assert.equal(acceptance.build.base, lock.build_base.reference)
  assert.equal(acceptance.build.nginx_V, nginxV())
  assert.deepEqual(Object.keys(acceptance.evidence).sort(), ['openresty-V.txt', 'runtime-apk-inventory.txt', 'runtime-build-inputs.sha256', 'runtime-export.json', 'runtime-sources.lock.json', 'source-verification.json'])
  assert.equal(acceptance.evidence['runtime-build-inputs.sha256'], hash(recordedBuildInputs(f)))
  assert.deepEqual(acceptance.checks, Object.fromEntries(acceptanceChecks.map((name) => [name, 'PASS'])))
  const probe = acceptance.files.find((file) => file.path === 'runtime/bin/h3probe')
  assert.deepEqual(acceptance.h3probe, { path: 'runtime/bin/h3probe', sha256: probe.sha256, go: 'go1.27.3',
    module: 'github.com/cdnca/cdnca/edge/openresty/http3/client', quic_go: 'v0.54.0',
    builder: 'golang@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201',
    deps: h3probeDeps(f.repo).map(({ path, version, sum }) => ({ path, version, sum })),
    settings: { '-buildmode': 'exe', '-compiler': 'gc', '-trimpath': 'true', CGO_ENABLED: '0', GOARCH: 'amd64', GOOS: 'linux', GOAMD64: 'v1' } })
  assert.equal(acceptance.files.find((file) => file.path === 'lua/share/cdnca/range/guard.lua').sha256, hash(fs.readFileSync(path.join(f.repo, 'edge/openresty/range/guard.lua'))))
  assert.equal(fs.statSync(f.output).mode & 0o777, 0o444)
  const retry = nativeRuntimeAcceptanceRun(f)
  assert.notEqual(retry.status, 0)
  assert.match(retry.stderr, /output already exists/)
})

test('baseline reuse arguments no longer exist', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t)
  const result = nativeRuntimeAcceptanceRun(f, ['--baseline-dir', f.root])
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /arguments/)
  assert.equal(fs.existsSync(f.output), false)
})

for (const [name, mutate] of [
  ['wrong source', (x) => { x.source.commit = 'a'.repeat(40) }],
  ['wrong tree', (x) => { x.source.tree = 'b'.repeat(40) }],
  ['wrong schema', (x) => { x.schema = 'unknown' }],
  ['failed status', (x) => { x.status = 'FAIL' }],
  ['missing check', (x) => { delete x.checks.dynamic_modules }],
  ['failed check', (x) => { x.checks.http3_after_reload = 'FAIL' }],
  ['extra check', (x) => { x.checks.assumed = 'PASS' }],
  ['missing inventory', (x) => { x.files.pop() }],
  ['duplicate inventory', (x) => { x.files[1] = x.files[0] }],
  ['changed inventory', (x) => { x.files[0].sha256 = '0'.repeat(64) }],
]) {
  test(`rejects smoke ${name} without writing acceptance`, (t) => {
    const f = nativeRuntimeAcceptanceFixture(t)
    mutate(f.smokeDocument); fs.writeFileSync(f.smoke, JSON.stringify(f.smokeDocument))
    const result = nativeRuntimeAcceptanceRun(f)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /smoke/)
    assert.equal(fs.existsSync(f.output), false)
  })
}

const evidenceFile = (f, name) => path.join(f.payload, 'evidence', name)
const replaceEvidence = (f, name, edit) => put(evidenceFile(f, name), edit(fs.readFileSync(evidenceFile(f, name), 'utf8')))
for (const [name, mutate, error] of [
  ['payload built before a committed recipe change', (f) => nativeRuntimeAcceptanceCommit(f, 'edge/openresty/native/build-openresty.sh', '\n# drift\n'), /build inputs/],
  ['payload built before a committed patch-set change', (f) => { fs.writeFileSync(path.join(f.repo, 'edge/openresty/native/patches/99-extra.patch'), 'extra\n'); nativeRuntimeAcceptanceCommit(f, 'edge/openresty/native/patches/99-extra.patch', '') }, /build inputs/],
  ['recorded input missing', (f) => replaceEvidence(f, 'runtime-build-inputs.sha256', (text) => text.split('\n').filter((line) => !line.includes('/test.patch')).join('\n')), /build inputs/],
  ['recorded input hash changed', (f) => replaceEvidence(f, 'runtime-build-inputs.sha256', (text) => text.replace(/^[0-9a-f]{64}(?=  \/source-contract\/build-openresty\.sh)/m, '0'.repeat(64))), /build inputs/],
  ['untracked file in the build context', (f) => { fs.writeFileSync(path.join(f.repo, 'edge/openresty/native/patches/local.patch'), 'local\n'); nativeRuntimeAcceptanceBuild(f) }, /build inputs/],
  ['Dockerfile copies an unrecorded input', (f) => nativeRuntimeAcceptanceCommit(f, 'edge/openresty/native/Dockerfile', '\nCOPY edge/openresty/runtime.env /source-contract/runtime.env\n'), /Dockerfile/],
  ['Lua mapping change', (f) => nativeRuntimeAcceptanceCommit(f, 'edge/openresty/native/Dockerfile', '\nCOPY edge/openresty/range/guard.lua /usr/local/share/cdnca/range/extra.lua\n'), /Lua source mapping/],
  ['stale Lua after a committed Lua change', (f) => nativeRuntimeAcceptanceCommit(f, 'edge/openresty/range/guard.lua', '\n-- drift\n'), /Lua/],
  ['payload Lua differs from its source', (f) => { put(path.join(f.payload, 'lua/l4geo/engine.lua'), 'changed'); nativeRuntimeAcceptanceResync(f) }, /Lua/],
  ['payload Lua missing', (f) => { fs.chmodSync(path.join(f.payload, 'lua/l4geo'), 0o755); fs.unlinkSync(path.join(f.payload, 'lua/l4geo/engine.lua')); nativeRuntimeAcceptanceResync(f) }, /Lua/],
  ['payload Lua executable', (f) => { fs.chmodSync(path.join(f.payload, 'lua/l4geo/engine.lua'), 0o555) }, /lua\/l4geo\/engine.lua/],
  ['extra runtime file outside the export', (f) => { put(path.join(f.payload, 'runtime/lib/extra.so'), 'unknown') }, /export/],
  ['export tamper', (f) => put(evidenceFile(f, 'runtime-export.json'), '{}'), /export/],
  ['OpenResty aliases differ', (f) => { put(path.join(f.payload, 'runtime/openresty/bin/openresty'), 'other\n', 0o555); nativeRuntimeAcceptanceResync(f) }, /aliases/],
  ['missing native loader', (f) => { fs.unlinkSync(path.join(f.payload, 'runtime/lib/ld-musl-x86_64.so.1')); nativeRuntimeAcceptanceResync(f) }, /runtime\/lib\/ld-musl-x86_64.so.1/],
  ['source lock evidence differs', (f) => put(evidenceFile(f, 'runtime-sources.lock.json'), '{}'), /source lock/],
  ['build source verification differs', (f) => replaceEvidence(f, 'source-verification.json', (text) => text.replace('"patches":1', '"patches":2')), /source verification/],
  ['wrong OpenResty version', (f) => put(evidenceFile(f, 'openresty-V.txt'), nginxV('1.27.1.2')), /nginx -V/],
  ['wrong OpenSSL', (f) => put(evidenceFile(f, 'openresty-V.txt'), nginxV('1.31.1.1', '3.5.0')), /nginx -V/],
  ['missing JA4 module', (f) => put(evidenceFile(f, 'openresty-V.txt'), nginxV().replace(' --add-module=/tmp/openresty-source/bundle/cdnca-ja4', '')), /nginx -V/],
  ['missing Brotli module', (f) => put(evidenceFile(f, 'openresty-V.txt'), nginxV().replace(' --add-module=/tmp/openresty-source/bundle/ngx_brotli', '')), /nginx -V/],
  ['missing HTTP/3', (f) => put(evidenceFile(f, 'openresty-V.txt'), nginxV().replace(' --with-http_v3_module', '')), /nginx -V/],
  ['missing build evidence', (f) => { fs.chmodSync(path.join(f.payload, 'evidence'), 0o755); fs.unlinkSync(evidenceFile(f, 'openresty-V.txt')) }, /evidence/],
  ['payload directory link', (f) => { fs.symlinkSync(f.payload, path.join(f.root, 'linked')); f.payload = path.join(f.root, 'linked') }, /directory/],
  ['runtime directory link', (f) => { fs.renameSync(path.join(f.payload, 'runtime/lib'), path.join(f.payload, 'runtime/lib-real')); fs.symlinkSync('lib-real', path.join(f.payload, 'runtime/lib')) }, /link/],
  ['runtime hardlink', (f) => { fs.linkSync(path.join(f.payload, 'lua/l4geo/engine.lua'), path.join(f.payload, 'lua/l4geo/extra.lua')) }, /link/],
  ['payload without h3probe', (f) => { fs.chmodSync(path.join(f.payload, 'runtime/bin'), 0o755); fs.unlinkSync(path.join(f.payload, 'runtime/bin/h3probe')); nativeRuntimeAcceptanceResync(f) }, /h3probe/],
  ['h3probe built by another Go', (f) => { f.h3probe = { go: 'go1.24.3' }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*Go/],
  ['h3probe linked against another quic-go', (f) => { f.h3probe = { deps: h3probeDeps(f.repo).map((dep) => dep.path.endsWith('/quic-go') ? { ...dep, version: 'v0.54.1' } : dep) }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*client\.sum/],
  ['h3probe dependency hash not in client.sum', (f) => { f.h3probe = { deps: h3probeDeps(f.repo).map((dep) => dep.path.endsWith('/x/net') ? { ...dep, sum: 'h1:' + 'A'.repeat(43) + '=' } : dep) }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*client\.sum/],
  ['h3probe built with cgo', (f) => { f.h3probe = { settings: { '-trimpath': 'true', CGO_ENABLED: '1', GOARCH: 'amd64', GOOS: 'linux' } }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*build settings/],
  ['h3probe built without trimpath', (f) => { f.h3probe = { settings: { CGO_ENABLED: '0', GOARCH: 'amd64', GOOS: 'linux' } }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*build settings/],
  ['h3probe of another module', (f) => { f.h3probe = { module: 'example.invalid/h3probe' }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*module/],
  ['dynamically linked h3probe', (f) => { f.h3probe = { dynamic: true }; nativeRuntimeAcceptanceBuild(f) }, /h3probe.*static/],
  ['h3probe executable bit missing', (f) => { fs.chmodSync(path.join(f.payload, 'runtime/bin/h3probe'), 0o444) }, /runtime\/bin\/h3probe/],
  ['h3probe builder differs from versions.env', (f) => nativeRuntimeAcceptanceCommit(f, 'edge/openresty/http3/versions.env', 'HTTP3_CLIENT_BUILDER=golang@sha256:' + '0'.repeat(64) + '\n'), /h3probe builder/],
  ['source archive tamper', (f) => { fs.appendFileSync(f.archive, 'changed') }, /source archive hash/],
  ['working verifier drift', (f) => { fs.appendFileSync(path.join(f.repo, 'edge/openresty/native/verify-sources.mjs'), '\n// drift\n') }, /working source/],
  ['uncommitted Lua drift', (f) => { fs.appendFileSync(path.join(f.repo, 'edge/openresty/range/guard.lua'), '\n-- uncommitted\n') }, /working source/],
]) {
  test(`rejects ${name} without writing acceptance`, (t) => {
    const f = nativeRuntimeAcceptanceFixture(t)
    mutate(f)
    const result = nativeRuntimeAcceptanceRun(f)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, error)
    assert.equal(fs.existsSync(f.output), false)
  })
}

test('actual patch postimage mismatch cannot become PASS', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t, (lock) => { lock.patches[0].files[0].after = '0'.repeat(64) })
  const result = nativeRuntimeAcceptanceRun(f)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /postimage/)
  assert.equal(fs.existsSync(f.output), false)
})

test('real valid OpenPGP signature with the wrong locked signer is rejected', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t, (lock) => { lock.source.signer.fingerprint = '0'.repeat(40) })
  const result = nativeRuntimeAcceptanceRun(f)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /unexpected source signer/)
  assert.equal(fs.existsSync(f.output), false)
})

test('native Dockerfile exporter records the build inputs and nginx -V the acceptance verifies', () => {
  const dockerfile = fs.readFileSync(path.join(repository, 'edge/openresty/native/Dockerfile'), 'utf8')
  const exporter = dockerfile.slice(dockerfile.indexOf('AS exporter'), dockerfile.indexOf('AS native-payload'))
  assert.match(exporter, /find \/source-contract \/native-node-export\.mjs \/h3probe-src -type f \| LC_ALL=C sort \| xargs sha256sum > \/native-payload\/evidence\/runtime-build-inputs\.sha256/)
  // h3probe: built in its own stage from the committed client module, placed where the exporter takes it.
  const env = Object.fromEntries(fs.readFileSync(path.join(repository, 'edge/openresty/http3/versions.env'), 'utf8').trim().split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2)))
  assert.ok(dockerfile.includes(`FROM ${env.HTTP3_CLIENT_BUILDER} AS h3probe\n`))
  assert.match(exporter, /COPY --from=h3probe \/h3probe-src \/h3probe-src/)
  assert.match(exporter, /COPY --from=runtime \/usr\/local\/bin\/h3probe \/native-root\/usr\/local\/bin\/h3probe/)
  assert.match(exporter, /\/usr\/local\/openresty\/bin\/openresty -V > \/native-payload\/evidence\/openresty-V\.txt 2>&1/)
  assert.ok(exporter.indexOf('openresty-V.txt') < exporter.indexOf('chmod 0444 /native-payload/evidence/*'))
})

for (const failure of ['fsyncSync', 'closeSync']) {
  test(`failed output ${failure} does not leave a successful acceptance file`, (t) => {
    const f = nativeRuntimeAcceptanceFixture(t)
    const injection = path.join(f.root, 'output-fault.mjs')
    fs.writeFileSync(injection, `import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
const open = fs.openSync, original = fs.${failure}
let target
fs.openSync = (...args) => { const fd = open(...args); if (args[1] === 'wx' && String(args[0]).endsWith('/evidence/runtime-acceptance.json')) target = fd; return fd }
fs.${failure} = (fd) => { if (fd === target) { target = undefined; ${failure === 'closeSync' ? 'original(fd);' : ''} throw new Error('fixture output ${failure} failure') } return original(fd) }
syncBuiltinESMExports()
`)
    const result = nativeRuntimeAcceptanceRun(f, [], ['--import', injection])
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, new RegExp(`fixture output ${failure} failure`))
    assert.equal(fs.existsSync(f.output), false)
  })
}

test('existing output and duplicate CLI flags cannot be overwritten or ignored', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t)
  fs.chmodSync(path.join(f.payload, 'evidence'), 0o755)
  fs.writeFileSync(f.output, 'existing evidence')
  const result = nativeRuntimeAcceptanceRun(f)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /output already exists/)
  assert.equal(fs.readFileSync(f.output, 'utf8'), 'existing evidence')
  const duplicate = nativeRuntimeAcceptanceRun(f, ['--source-commit', f.commit])
  assert.notEqual(duplicate.status, 0)
  assert.match(duplicate.stderr, /arguments/)
})

test('private publisher umask still produces the required immutable 0444 evidence', (t) => {
  const f = nativeRuntimeAcceptanceFixture(t)
  const injection = path.join(f.root, 'private-umask.mjs')
  fs.writeFileSync(injection, 'process.umask(0o077)\n')
  const result = nativeRuntimeAcceptanceRun(f, [], ['--import', injection])
  assert.equal(result.status, 0, result.stderr)
  assert.equal(fs.statSync(f.output).mode & 0o777, 0o444)
})

test('goBuildInfo reads the Go version, module, dependencies and build settings', () => {
  const deps = [{ path: 'github.com/quic-go/quic-go', version: 'v0.54.0', sum: 'h1:6s1YB9QotYI6Ospeiguknbp2Znb/jZYjZLRXn9kMQBg=' }]
  const info = goBuildInfo(goBuildInfoELF({ deps }))
  assert.equal(info.go, 'go1.27.3')
  assert.equal(info.path, 'github.com/cdnca/cdnca/edge/openresty/http3/client')
  assert.deepEqual(info.deps, deps)
  assert.equal(info.settings.CGO_ENABLED, '0')
  assert.throws(() => goBuildInfo(Buffer.from('not an ELF')), /buildinfo/)
})
