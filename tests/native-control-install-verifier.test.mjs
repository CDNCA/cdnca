import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { hostEd25519Tool } from './helpers/ed25519-tool-host.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
// The verifier reads the installer pin; tests pin the host build of the tool.
const verifier = `CDNCA_ED25519_TOOL_SHA256=${hostEd25519Tool().sha256}\n` + source.match(/verify_native_install_package\(\) \{[\s\S]*?\n\}/)?.[0]
const domain = 'cdnca.native-management.install/v1\n'
const key = generateKeyPairSync('ed25519')
const elf = Buffer.alloc(80)
Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf)
elf.writeUInt16LE(3, 16); elf.writeUInt16LE(62, 18)

function nativeControlInstallVerificationTar(members) {
  return Buffer.concat([...members.flatMap((item) => {
    const body = Buffer.from(item.body), header = Buffer.alloc(512)
    assert.ok(Buffer.byteLength(item.path) <= 100)
    header.write(item.path, 0, 100)
    for (const [offset, value, width] of [[100, item.mode, 7], [108, item.uid ?? 0, 7], [116, 0, 7], [124, body.length, 11], [136, item.mtime ?? 0, 11]]) {
      header.write(value.toString(8).padStart(width, '0') + '\0', offset)
    }
    header.fill(32, 148, 156)
    header.write(item.type ?? '0', 156); header.write(item.link ?? '', 157, 100)
    header.write('ustar\0' + '00', 257)
    if (item.binaryNumeric) {
      header.fill(0, item.binaryNumeric, item.binaryNumeric + 8)
      header.writeBigUInt64BE((1n << 63n) | BigInt(item.mode), item.binaryNumeric)
    }
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148)
    return [header, body, Buffer.alloc((512 - body.length % 512) % 512)]
  }), Buffer.alloc(1024)])
}

function nativeControlInstallVerificationFixture(options = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-control-install-verifier.')))
  const metadata = { schema: 'cdnca.native-management.release/v1', version: '1.2.3', built_at: '2026-10-08T00:00:00Z',
    source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), previous_commit: 'c'.repeat(40) },
    platform: { os: 'linux', arch: 'amd64' }, files: [{ path: 'fixture' }] }
  if (options.v2) Object.assign(metadata, { schema: 'cdnca.native-management.release/v2', key_id: 'fixture' })
  options.sidecar?.(metadata)
  const sidecarBytes = Buffer.from(JSON.stringify(metadata))
  const innerSignature = sign(null, Buffer.concat([Buffer.from('cdnca.native-management.release/v2\n'), sidecarBytes]), key.privateKey).toString('base64') + '\n'
  const files = [
    { path: 'native-management.tar', body: Buffer.alloc(1024), mode: 0o600 },
    options.v2 ? { path: 'release.manifest.sig', body: innerSignature, mode: 0o644 } : { path: 'source.bundle', body: '# v2 git bundle\n', mode: 0o600 },
    { path: 'release.manifest.json', body: sidecarBytes, mode: 0o644 },
    { path: 'control-upgrade-runner', body: elf, mode: 0o755 },
    { path: 'analytics-history-bootstrap', body: elf, mode: 0o755 },
    { path: 'nats-server', body: elf, mode: 0o755 },
    { path: 'NATS-LICENSE', body: 'NATS test license\n', mode: 0o644 },
    { path: 'cdnca-ed25519', body: options.tool ?? hostEd25519Tool().bytes, mode: 0o755 },
    ...['install-ubuntu-dependencies.sh', 'configure-clickhouse.py', 'configure-nats.py', 'native-nats-profile.json',
      'install-rustfs.py', 'rustfs-1.0.1.json', 'install-native-baseline.py', 'configure-control-runtime.py',
      'configure-certificate-runtime.py', 'configure-native-upgrade.py']
      .map((name) => ({ path: `scripts/native-runtime/${name}`, mode: name.endsWith('.sh') ? 0o755 : 0o644,
        body: 'exit 99 # fixture must never execute\n' })),
    { path: 'deploy/systemd/install-native-control-upgrade-runner.sh', body: 'exit 99\n', mode: 0o755 },
    { path: 'scripts/install-node.sh', body: 'exit 99\n', mode: 0o755 },
    ...readdirSync(new URL('../infra/clickhouse/migrations/', import.meta.url)).filter((name) => name.endsWith('.up.sql'))
      .map((name) => ({ path: `infra/clickhouse/migrations/${name}`, body: '-- fixture\n', mode: 0o644 })),
  ].sort((a, b) => a.path < b.path ? -1 : 1)
  options.files?.(files)
  const signingDomain = options.v2 ? 'cdnca.native-management.install/v2\n' : domain
  const manifest = { schema: signingDomain.trim(), key_id: 'fixture', version: '1.2.3', built_at: '2026-10-08T00:00:00Z',
    source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), previous_commit: 'c'.repeat(40) }, platform: { os: 'linux', arch: 'amd64' },
    files: files.map((file) => ({ path: file.path, bytes: Buffer.byteLength(file.body), mode: file.mode,
      sha256: createHash('sha256').update(file.body).digest('hex') })) }
  options.manifest?.(manifest)
  const encoded = Buffer.from(options.encode ? options.encode(manifest) : JSON.stringify(manifest))
  const members = [{ path: 'install.manifest.json', body: encoded, mode: 0o644 },
    { path: 'install.manifest.sig', body: sign(null, Buffer.concat([Buffer.from(options.domain ?? signingDomain), encoded]), key.privateKey).toString('base64') + '\n', mode: 0o644 }, ...files]
  options.members?.(members)
  const trust = { version: 1, keys: [{ key_id: 'fixture', public_key_pem: key.publicKey.export({ type: 'spki', format: 'pem' }) }] }
  options.trust?.(trust)
  writeFileSync(join(root, 'package.tar'), Buffer.concat([nativeControlInstallVerificationTar(members), options.trailing ?? Buffer.alloc(0)]), { mode: 0o600 })
  writeFileSync(join(root, 'trust.json'), JSON.stringify(trust), { mode: 0o600 })
  return { root, destination: join(root, 'verified'), files }
}

function nativeControlInstallVerificationRun(fixture, environment = {}) {
  assert.ok(verifier, 'trusted outer verifier must be shipped in install-control.sh')
  return spawnSync('bash', ['-c', 'set -euo pipefail\numask 077\n' + verifier.replace('OWNER = 0', `OWNER = ${process.getuid()}`) +
    '\nverify_native_install_package "$1" "$2" "$3"', 'fixture', join(fixture.root, 'package.tar'), join(fixture.root, 'trust.json'), fixture.destination],
  { encoding: 'utf8', timeout: 15000, env: { ...process.env, ...environment } })
}

test('FIFO input is rejected without waiting for a writer', () => {
  const fixture = nativeControlInstallVerificationFixture()
  try {
    rmSync(join(fixture.root, 'package.tar'))
    assert.equal(spawnSync('mkfifo', [join(fixture.root, 'package.tar')]).status, 0)
    const result = nativeControlInstallVerificationRun(fixture)
    assert.equal(result.status, 1, result.stderr)
    assert.equal(result.error, undefined)
    assert.equal(existsSync(fixture.destination), false)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

// The installer accepts whatever contiguous 001..N ClickHouse set the signed
// manifest names (a later release adds 017+), and nothing else under infra/clickhouse.
const clickhouseCount = readdirSync(new URL('../infra/clickhouse/migrations/', import.meta.url)).filter((name) => name.endsWith('.up.sql')).length
const nextClickHouse = (number, name = 'later_release') => `infra/clickhouse/migrations/${String(number).padStart(3, '0')}_${name}.up.sql`
for (const [name, change, accepted] of [
  ['an appended migration', (files) => files.push({ path: nextClickHouse(clickhouseCount + 1), body: '-- next\n', mode: 0o644 }), true],
  ['a numbering gap', (files) => files.push({ path: nextClickHouse(clickhouseCount + 2), body: '-- gap\n', mode: 0o644 }), false],
  ['no migrations', (files) => files.splice(0, files.length, ...files.filter((file) => !file.path.startsWith('infra/'))), false],
  ['a down script', (files) => files.push({ path: nextClickHouse(clickhouseCount + 1).replace('.up.sql', '.down.sql'), body: '-- down\n', mode: 0o644 }), false],
  ['an executable migration', (files) => files.push({ path: nextClickHouse(clickhouseCount + 1), body: '-- next\n', mode: 0o755 }), false],
]) test(`installer ${accepted ? 'accepts' : 'rejects'} ClickHouse inventory with ${name}`, () => {
  const fixture = nativeControlInstallVerificationFixture({ files: (files) => { change(files); files.sort((a, b) => a.path < b.path ? -1 : 1) } })
  try {
    const result = nativeControlInstallVerificationRun(fixture)
    assert.equal(result.status, accepted ? 0 : 1, result.stderr)
    assert.equal(existsSync(join(fixture.destination, nextClickHouse(clickhouseCount + 1))), accepted)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

test('v2 verifies detached inner and outer signatures without shipping source', () => {
  const fixture = nativeControlInstallVerificationFixture({ v2: true })
  try {
    const result = nativeControlInstallVerificationRun(fixture)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(existsSync(join(fixture.destination, 'source.bundle')), false)
    assert.equal(existsSync(join(fixture.destination, 'release.manifest.sig')), true)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

test('public v2 requirement never falls back to a correctly signed legacy source bundle', () => {
  const fixture = nativeControlInstallVerificationFixture()
  try {
    const result = spawnSync('bash', ['-c', 'set -euo pipefail\numask 077\n' + verifier.replace('OWNER = 0', `OWNER = ${process.getuid()}`) +
      '\nverify_native_install_package "$1" "$2" "$3" cdnca.native-management.install/v2', 'fixture',
    join(fixture.root, 'package.tar'), join(fixture.root, 'trust.json'), fixture.destination], { encoding: 'utf8', timeout: 15000 })
    assert.equal(result.status, 1)
    assert.equal(existsSync(fixture.destination), false)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

for (const [name, options] of [
  ['wrong inner signature despite valid outer', { files: (files) => { files.find((file) => file.path === 'release.manifest.sig').body = Buffer.alloc(64).toString('base64') } }],
  ['missing inner signature', { files: (files) => { files.splice(files.findIndex((file) => file.path === 'release.manifest.sig'), 1) } }],
  ['source bundle hidden in v2', { files: (files) => { files.push({ path: 'source.bundle', body: 'private-source', mode: 0o600 }); files.sort((a, b) => a.path < b.path ? -1 : 1) } }],
  ['untrusted inner key', { sidecar: (value) => { value.key_id = 'unknown' } }],
  ['v1 inner with v2 outer', { sidecar: (value) => { value.schema = 'cdnca.native-management.release/v1'; delete value.key_id } }],
  ['extra inner field', { sidecar: (value) => { value.extra = true } }],
]) test(`v2 rejects ${name} before extraction`, () => {
  const fixture = nativeControlInstallVerificationFixture({ v2: true, ...options })
  try {
    assert.equal(nativeControlInstallVerificationRun(fixture).status, 1)
    assert.equal(existsSync(fixture.destination), false)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

test('archive mutation after successful signature verification cannot produce accepted output', () => {
  // A pinned tool that verifies correctly and then changes the archive: the
  // post-read metadata check must still reject the package.
  const mutatingDirectory = mkdtempSync(join(tmpdir(), 'cdnca-mutating-tool-'))
  const archivePath = join(mutatingDirectory, 'package-path')
  const mutating = Buffer.from(`#!/bin/bash\n"${hostEd25519Tool().path}" "$@" || exit 1\n[ "$1" != verify ] || printf x >>"$(cat '${archivePath}')"\n`)
  const fixture = nativeControlInstallVerificationFixture({ tool: mutating })
  try {
    writeFileSync(archivePath, join(fixture.root, 'package.tar'))
    const pinned = verifier.replace(/^CDNCA_ED25519_TOOL_SHA256=[a-f0-9]{64}$/m, `CDNCA_ED25519_TOOL_SHA256=${createHash('sha256').update(mutating).digest('hex')}`)
    const result = spawnSync('bash', ['-c', 'set -euo pipefail\numask 077\n' + pinned.replace('OWNER = 0', `OWNER = ${process.getuid()}`) +
      '\nverify_native_install_package "$1" "$2" "$3"', 'fixture', join(fixture.root, 'package.tar'), join(fixture.root, 'trust.json'), fixture.destination],
    { encoding: 'utf8', timeout: 15000 })
    assert.equal(result.status, 1, result.stderr)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /no downloaded code was executed/)
  } finally { rmSync(fixture.root, { recursive: true }); rmSync(mutatingDirectory, { recursive: true }) }
})

test('a signed package whose Ed25519 tool differs from the installer pin is rejected before the tool runs', () => {
  const marker = join(mkdtempSync(join(tmpdir(), 'cdnca-unpinned-tool-')), 'executed')
  // Correctly signed and listed, but not the pinned build: it must never execute.
  const fixture = nativeControlInstallVerificationFixture({ tool: Buffer.from(`#!/bin/sh\ntouch '${marker}'\nexit 0\n`) })
  try {
    const result = nativeControlInstallVerificationRun(fixture)
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stderr, /no downloaded code was executed/)
    assert.equal(existsSync(marker), false)
    assert.equal(existsSync(fixture.destination), false)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

test('full signed inventory verifies before extraction and never executes a helper or fixture ELF', () => {
  const fixture = nativeControlInstallVerificationFixture()
  try {
    const result = nativeControlInstallVerificationRun(fixture)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(JSON.parse(result.stdout).status, 'signed_install_package_verified')
    for (const file of fixture.files) {
      assert.deepEqual(readFileSync(join(fixture.destination, file.path)), Buffer.from(file.body))
      assert.equal(statSync(join(fixture.destination, file.path)).mode & 0o777, file.mode)
    }
    assert.equal(statSync(fixture.destination).mode & 0o777, 0o700)
    const again = nativeControlInstallVerificationRun(fixture)
    assert.notEqual(again.status, 0)
  } finally { rmSync(fixture.root, { recursive: true }) }
})

for (const [name, options] of [
  ['signature domain', { domain: 'other-domain\n' }],
  ['signature bytes', { members: (m) => { m[1].body = Buffer.alloc(64).toString('base64') } }],
  ['unknown signing key', { manifest: (m) => { m.key_id = 'unknown' } }],
  ['duplicate trust key', { trust: (t) => { t.keys.push(t.keys[0]) } }],
  ['schema', { manifest: (m) => { m.schema = 'legacy' } }],
  ['extra field', { manifest: (m) => { m.extra = true } }],
  ['duplicate JSON', { encode: (m) => JSON.stringify(m).replace('"schema":', '"schema":"old","schema":') }],
  ['development version', { manifest: (m) => { m.version = 'development' } }],
  ['non-canonical version', { manifest: (m) => { m.version = '1.02.3' } }],
  ['invalid date', { manifest: (m) => { m.built_at = '2026-19-45T00:00:00Z' } }],
  ['wrong platform', { manifest: (m) => { m.platform.arch = 'arm64' } }],
  ['self predecessor', { manifest: (m) => { m.source.previous_commit = m.source.commit } }],
  ['symbolic source', { manifest: (m) => { m.source.commit = 'main' } }],
  ['Boolean bytes', { manifest: (m) => { m.files[0].bytes = true } }],
  ['oversized file', { manifest: (m) => { m.files[0].bytes = 1 << 30 } }],
  ['unsorted inventory', { manifest: (m) => { m.files.reverse() } }],
  ['incomplete inventory', { manifest: (m) => { m.files.pop() } }],
  ['modified payload', { members: (m) => { m[3].body = 'tampered' } }],
  ['non-ELF runner', { files: (f) => { f.find((v) => v.path === 'control-upgrade-runner').body = '#!/bin/sh\nexit 0' } }],
  ['non-ELF analytics bootstrap', { files: (f) => { f.find((v) => v.path === 'analytics-history-bootstrap').body = '#!/bin/sh\nexit 0' } }],
  ['wrong-architecture analytics bootstrap', { files: (f) => { const value = Buffer.from(elf); value.writeUInt16LE(183, 18); f.find((v) => v.path === 'analytics-history-bootstrap').body = value } }],
  ['missing analytics bootstrap', { files: (f) => { f.splice(f.findIndex((v) => v.path === 'analytics-history-bootstrap'), 1) } }],
  ['missing NATS server', { files: (f) => { f.splice(f.findIndex((v) => v.path === 'nats-server'), 1) } }],
  ['missing NATS license', { files: (f) => { f.splice(f.findIndex((v) => v.path === 'NATS-LICENSE'), 1) } }],
  ['non-ELF NATS server', { files: (f) => { f.find((v) => v.path === 'nats-server').body = '#!/bin/sh\nexit 0' } }],
  ['wrong-architecture NATS server', { files: (f) => { const value = Buffer.from(elf); value.writeUInt16LE(183, 18); f.find((v) => v.path === 'nats-server').body = value } }],
  ['unapproved executable', { files: (f) => { f.find((v) => v.path.endsWith('configure-nats.py')).mode = 0o755 } }],
  ['missing helper', { files: (f) => { f.pop() } }],
  ['symlink', { members: (m) => { m[3].type = '2'; m[3].link = '/etc/passwd' } }],
  ['hardlink', { members: (m) => { m[3].type = '1'; m[3].link = m[2].path } }],
  ['extended header', { members: (m) => { m[3].type = 'x' } }],
  ['nonzero owner', { members: (m) => { m[3].uid = 501 } }],
  ['nonzero mtime', { members: (m) => { m[3].mtime = 1 } }],
  ['GNU base256 mode', { members: (m) => { m[3].binaryNumeric = 100 } }],
  ['duplicate member', { members: (m) => { m.push(m[3]) } }],
  ['absolute path', { members: (m) => { m[3].path = '/tmp/escape' } }],
  ['parent escape', { members: (m) => { m[3].path = '../escape' } }],
  ['unlisted member', { members: (m) => { m.push({ path: 'run-me.sh', body: 'exit 99', mode: 0o755 }) } }],
  ['trailing archive', { trailing: nativeControlInstallVerificationTar([{ path: 'hidden', body: 'x', mode: 0o644 }]) }],
  ['mismatched signed sidecar', { sidecar: (m) => { m.source.commit = 'd'.repeat(40) } }],
]) {
  test(`reject ${name} before creating the destination`, () => {
    const fixture = nativeControlInstallVerificationFixture(options)
    try {
      const result = nativeControlInstallVerificationRun(fixture)
      assert.notEqual(result.status, 0, name)
      assert.match(result.stderr, /native install package rejected/)
      assert.equal(result.stdout, '')
      assert.equal(existsSync(fixture.destination), false)
    } finally { rmSync(fixture.root, { recursive: true }) }
  })
}

test('input hardlinks, symlinks, and an existing output are not followed or overwritten', () => {
  for (const kind of ['hardlink', 'symlink', 'existing output']) {
    const fixture = nativeControlInstallVerificationFixture()
    try {
      const archive = join(fixture.root, 'package.tar')
      if (kind === 'hardlink') linkSync(archive, join(fixture.root, 'alias'))
      else if (kind === 'symlink') {
        linkSync(archive, join(fixture.root, 'alias')); rmSync(archive); symlinkSync(join(fixture.root, 'alias'), archive)
      } else writeFileSync(fixture.destination, 'previous bytes')
      assert.notEqual(nativeControlInstallVerificationRun(fixture).status, 0)
      if (kind === 'existing output') assert.equal(readFileSync(fixture.destination, 'utf8'), 'previous bytes')
      else assert.equal(existsSync(fixture.destination), false)
    } finally { rmSync(fixture.root, { recursive: true }) }
  }
})
