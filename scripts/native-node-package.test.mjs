import test from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { gunzipSync } from 'node:zlib'
import { createNativeNodeManifest, finalizeNativeNodePackage } from './native-node-package.mjs'

const metadata = {
  version: '1.0.2', key_id: 'native-node-test',
  source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
  platform: { os: 'linux', arch: 'amd64' },
  runtime: { openresty_version: '1.31.1.1', nginx_version: '1.31.1',
    source_sha256: 'c'.repeat(64), patch_manifest_sha256: 'd'.repeat(64), release_eligible: true },
}

const required = [
  'bin/edge-agent', 'runtime/openresty/bin/openresty', 'runtime/openresty/nginx/sbin/nginx', 'runtime/openresty/lualib/resty/ipmatcher.lua',
  'runtime/lib/ld-musl-x86_64.so.1', 'runtime/bin/h3probe',
  'lua/share/cdnca/range/guard.lua', 'lua/share/cdnca/security/cdnca_waf.lua', 'lua/share/cdnca/security/cdnca_rule_interp.lua', 'lua/share/cdnca/security/cdnca_banlist.lua', 'lua/share/cdnca/dynroute/cdnca_site.lua', 'lua/share/cdnca/dynroute/cdnca_site_admin.lua', 'lua/share/cdnca/dynroute/cdnca_tls.lua', 'lua/share/cdnca/dynroute/cdnca_origin.lua', 'lua/share/cdnca/dynroute/cdnca_originauth.lua', 'lua/share/cdnca/dynroute/cdnca_origintls.lua', 'lua/share/cdnca/dynroute/cdnca_cache.lua', 'lua/share/cdnca/dynroute/cdnca_filters.lua', 'lua/share/cdnca/dynroute/cdnca_limits.lua',
  'lua/share/cdnca/security/cc.lua', 'lua/share/cdnca/security/cc_adaptive.lua',
  'lua/share/cdnca/security/url_auth.lua', 'lua/share/cdnca/challenge/engine.lua',
  'lua/share/cdnca/challenge/crypto.lua', 'lua/share/cdnca/challenge/ip.lua',
  'lua/l4geo/engine.lua', 'lua/l4geo/cdnca_l4_geo.lua',
  'lua/share/cdnca/security/cdnca_iplib.lua', 'lua/l4geo/cdnca_iplib.lua',
  'lua/share/cdnca/httppolicy/engine.lua', 'lua/share/cdnca/firewallaction/engine.lua', 'lua/share/cdnca/siteaccess/engine.lua', 'lua/share/cdnca/errorpage/handler.lua', 'lua/share/cdnca/originauth/engine.lua', 'lua/share/cdnca/originauth/crypto.lua', 'lua/share/cdnca/dynroute/cdnca_dynroute.lua', 'lua/share/cdnca/sched302/cdnca_sched302.lua', 'lua/share/cdnca/dynroute/cdnca_telemetry.lua', 'lua/share/cdnca/dynroute/cdnca_webp.lua', 'lua/share/cdnca/dynroute/cdnca_webp_codec.lua', 'lua/share/cdnca/dynroute/cdnca_security.lua', 'lua/share/cdnca/dynroute/cdnca_managed_waf.lua', 'lua/share/cdnca/dynroute/cdnca_rule_plan.lua', 'lua/share/cdnca/dynroute/cdnca_bot.lua',
  'bin/cdnca-edge-agent-helper',
  ...['install', 'lib', 'preflight', 'rollback', 'uninstall', 'upgrade'].map((name) => `packaging/scripts/${name}.sh`),
  'packaging/systemd/cdnca-edge-agent.service', 'packaging/systemd/cdnca-edge-agent-root.service',
  'packaging/systemd/cdnca-edge-agent-helper.service', 'packaging/systemd/cdnca-edge-agent-helper.socket',
  'packaging/sysusers/cdnca-edge-agent.conf', 'packaging/tmpfiles/cdnca-edge-agent.conf',
  'packaging/tmpfiles/cdnca-edge-agent-root.conf', 'packaging/logrotate/cdnca-edge-agent',
  'packaging/config/agent.env', 'packaging/config/config.example.json', 'packaging/README.md',
  'upgrade/manifest', 'upgrade/manifest.sig', 'upgrade/package-signing.pem', 'evidence/edge-agent.spdx.json',
]
const executable = (name) => name.startsWith('bin/') || name.startsWith('runtime/') && !name.endsWith('.lua') || name.startsWith('packaging/scripts/')
const releaseKey = generateKeyPairSync('ed25519')
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex')

// A canonical manifest v2 for the fixture Agent and SBOM, signed by the
// packaged release key; overrides model a mis-assembled package.
function writeUpgradeInputs(payload, overrides = {}) {
  const agent = fs.readFileSync(path.join(payload, 'bin/edge-agent'))
  const sbom = fs.readFileSync(path.join(payload, 'evidence/edge-agent.spdx.json'))
  const fields = { manifest_version: '2', release_sequence: '7', version: '1.0.2', artifact_path: 'edge-agent',
    artifact_sha256: sha(agent), artifact_size: String(agent.length), sbom_path: 'edge-agent.spdx.json',
    sbom_sha256: sha(sbom), sbom_size: String(sbom.length), os: 'linux', arch: 'amd64',
    source_repository: 'https://example.invalid/cdnca.git', source_commit: 'a'.repeat(40),
    build_time: '2026-07-22T00:00:00Z', minimum_control_protocol: '1.0', minimum_agent_protocol: '1.0', ...overrides }
  const manifest = Buffer.from(Object.entries(fields).map(([key, value]) => `${key}=${value}\n`).join(''))
  const replace = (name, bytes) => {
    const target = path.join(payload, name)
    fs.chmodSync(target, 0o644); fs.writeFileSync(target, bytes); fs.chmodSync(target, 0o444)
  }
  replace('upgrade/manifest', manifest)
  replace('upgrade/manifest.sig', sign(null, manifest, overrides.signingKey ?? releaseKey.privateKey))
  replace('upgrade/package-signing.pem', releaseKey.publicKey.export({ type: 'spki', format: 'pem' }))
}

for (const failure of ['none', 'unbound source lock', 'wrong runtime version', 'changed runtime', 'unlisted runtime', 'reused acceptance', 'no h3probe acceptance']) {
  test(`prepare binds runtime evidence to pushed sources and exact payload: ${failure}`, (t) => {
    const { directory, payload } = fixture(t)
    const hash = (bytes) => createHash('sha256').update(bytes).digest('hex')
    const lock = Buffer.from(JSON.stringify({ schema: 'cdnca.native-openresty.sources/v1', source: {
      version: '1.31.1.1', nginx_core: '1.31.1', sha256: 'c'.repeat(64),
    } }))
    const runtime = { ...metadata.runtime, patch_manifest_sha256: hash(lock) }
    const base = createNativeNodeManifest(payload, { ...metadata, runtime })
    const files = base.files.filter((file) => /^(runtime|lua)\//.test(file.path)).map(({ path, sha256 }) => ({ path, sha256 }))
    const evidence = { schema: 'cdnca.native-node.runtime-acceptance/v1', source: metadata.source, runtime, files,
      checks: Object.fromEntries(['source_signature', 'patches', 'native_loader', 'h3probe', 'http1', 'http2', 'http3', 'stream', 'lua', 'reload'].map((name) => [name, 'PASS'])) }
    if (failure === 'no h3probe acceptance') delete evidence.checks.h3probe
    if (failure === 'wrong runtime version') evidence.runtime.openresty_version = '1.99.1.1'
    if (failure === 'reused acceptance') evidence.files[0].sha256 = '0'.repeat(64)
    fs.writeFileSync(path.join(payload, 'evidence/runtime-acceptance.json'), JSON.stringify(evidence), { mode: 0o444 })
    fs.writeFileSync(path.join(payload, 'evidence/runtime-export.json'), JSON.stringify({ schema: 'cdnca.native-node.runtime-export/v1', files }), { mode: 0o444 })
    fs.writeFileSync(path.join(payload, 'evidence/runtime-sources.lock.json'), failure === 'unbound source lock' ? Buffer.from('{}') : lock, { mode: 0o444 })
    fs.writeFileSync(path.join(payload, 'evidence/edge-agent.provenance.json'), JSON.stringify({
      schema: 'cdnca.edge.release-provenance/v1', source_commit: metadata.source.commit,
      version: metadata.version, arch: 'amd64', artifact: { sha256: base.files.find((file) => file.path === 'bin/edge-agent').sha256 },
    }), { mode: 0o444 })
    if (failure === 'changed runtime') {
      const target = path.join(payload, 'runtime/lib/ld-musl-x86_64.so.1')
      fs.chmodSync(target, 0o755); fs.writeFileSync(target, 'changed runtime'); fs.chmodSync(target, 0o555)
    }
    if (failure === 'unlisted runtime') fs.writeFileSync(path.join(payload, 'runtime/lib/extra.so'), 'unverified', { mode: 0o444 })
    fs.mkdirSync(path.join(directory, 'tools'))
    fs.writeFileSync(path.join(directory, 'source-lock'), lock)
    fs.writeFileSync(path.join(directory, 'tools/git'), `#!/bin/sh
case "$1" in
  ls-remote) printf '%s\\t%s\\n' '${metadata.source.commit}' 'refs/heads/test' ;;
  rev-parse) printf '%s\\n' '${metadata.source.tree}' ;;
  show) case "$2" in
    *:edge/openresty/native/sources.lock.json) cat "$FIXTURE_SOURCE_LOCK" ;;
    *) exit 9 ;;
  esac ;;
  *) exit 8 ;;
esac
`, { mode: 0o755 })
    const result = spawnSync(process.execPath, ['scripts/native-node-package.mjs', 'prepare',
      '--source-commit', metadata.source.commit, '--remote-ref', 'refs/heads/test', '--version', metadata.version,
      '--key-id', metadata.key_id, '--payload-dir', payload, '--output-dir', path.join(directory, 'unsigned')], {
      cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8',
      env: { ...process.env, PATH: `${path.join(directory, 'tools')}:${process.env.PATH}`, FIXTURE_SOURCE_LOCK: path.join(directory, 'source-lock') },
    })
    assert.equal(result.status === 0, failure === 'none', result.stderr)
    if (failure !== 'none') assert.match(result.stderr, /runtime.*(?:source|evidence|payload)/)
  })
}

function fixture(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-node-test-')))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const payload = path.join(directory, 'payload')
  fs.mkdirSync(payload)
  for (const name of required) {
    fs.mkdirSync(path.dirname(path.join(payload, name)), { recursive: true })
    fs.writeFileSync(path.join(payload, name), 'test fixture only\n', { mode: executable(name) ? 0o555 : 0o444 })
  }
  writeUpgradeInputs(payload)
  return { directory, payload }
}

test('complete native node manifest binds every component and immutable source', (t) => {
  const { payload } = fixture(t)
  const manifest = createNativeNodeManifest(payload, metadata)
  assert.equal(manifest.schema, 'cdnca.native-node.release/v1')
  assert.deepEqual(manifest.source, metadata.source)
  assert.equal(manifest.files.length, required.length)
  assert.deepEqual(manifest.files.map((file) => file.path), [...required].sort())
  assert.ok(manifest.files.every((file) => /^[a-f0-9]{64}$/.test(file.sha256) && file.size > 0))
})

for (const name of required) {
  test(`rejects incomplete package missing ${name}`, (t) => {
    const { payload } = fixture(t)
    fs.unlinkSync(path.join(payload, name))
    assert.throws(() => createNativeNodeManifest(payload, metadata), /required/)
  })
}

for (const [name, change] of [
  ['development version', (m) => { m.version = 'development' }],
  ['leading zero version', (m) => { m.version = '01.0.2' }],
  ['unknown architecture', (m) => { m.platform.arch = 'arm64' }],
  ['short commit', (m) => { m.source.commit = 'a961491e' }],
  ['ineligible runtime', (m) => { m.runtime.release_eligible = false }],
  ['missing patch identity', (m) => { delete m.runtime.patch_manifest_sha256 }],
]) {
  test(`rejects ${name}`, (t) => {
    const { payload } = fixture(t), value = structuredClone(metadata)
    change(value)
    assert.throws(() => createNativeNodeManifest(payload, value), /metadata/)
  })
}

test('rejects symlinks, hard links, writable payloads and unexpected files', (t) => {
  const { payload } = fixture(t), extra = path.join(payload, 'evidence/extra')
  fs.symlinkSync('../bin/edge-agent', extra)
  assert.throws(() => createNativeNodeManifest(payload, metadata), /link/)
  fs.unlinkSync(extra)
  fs.linkSync(path.join(payload, 'bin/edge-agent'), extra)
  assert.throws(() => createNativeNodeManifest(payload, metadata), /link/)
  fs.unlinkSync(extra)
  fs.writeFileSync(extra, 'unsafe', { mode: 0o644 })
  assert.throws(() => createNativeNodeManifest(payload, metadata), /mode/)
  fs.unlinkSync(extra)
  fs.writeFileSync(path.join(payload, 'unexpected'), 'unsafe', { mode: 0o444 })
  assert.throws(() => createNativeNodeManifest(payload, metadata), /member/)
})

for (const [name, overrides] of [
  ['manifest v2 for another Agent', { artifact_sha256: '0'.repeat(64) }],
  ['manifest v2 for another SBOM size', { sbom_size: '1' }],
  ['manifest v2 for another architecture', { arch: 'arm64' }],
  ['manifest v2 signed by an unpackaged key', { signingKey: generateKeyPairSync('ed25519').privateKey }],
]) {
  test(`rejects a ${name}`, (t) => {
    const { payload } = fixture(t)
    const { signingKey, ...fields } = overrides
    writeUpgradeInputs(payload, fields)
    if (signingKey) {
      const manifest = fs.readFileSync(path.join(payload, 'upgrade/manifest'))
      const target = path.join(payload, 'upgrade/manifest.sig')
      fs.chmodSync(target, 0o644); fs.writeFileSync(target, sign(null, manifest, signingKey)); fs.chmodSync(target, 0o444)
    }
    assert.throws(() => createNativeNodeManifest(payload, metadata), /upgrade manifest/)
  })
}

test('packages without upgrade members are always rejected (no legacy inventory mode)', (t) => {
  const { payload } = fixture(t)
  for (const name of required.filter((entry) => /^(bin\/cdnca-edge-agent-helper|packaging\/|upgrade\/|evidence\/edge-agent\.spdx\.json)/.test(entry))) {
    fs.chmodSync(path.dirname(path.join(payload, name)), 0o755)
    fs.unlinkSync(path.join(payload, name))
  }
  for (const directory of ['packaging', 'upgrade']) fs.rmSync(path.join(payload, directory), { recursive: true, force: true })
  assert.throws(() => createNativeNodeManifest(payload, metadata), /required member: bin\/cdnca-edge-agent-helper/)
  assert.throws(() => createNativeNodeManifest(payload, metadata, { requireUpgradeInputs: false }), /required member: bin\/cdnca-edge-agent-helper/)
})

test('packaging scripts are executable and other packaging members are data', (t) => {
  const { payload } = fixture(t)
  fs.chmodSync(path.join(payload, 'packaging/scripts/upgrade.sh'), 0o444)
  assert.throws(() => createNativeNodeManifest(payload, metadata), /required member: packaging\/scripts\/upgrade.sh/)
  fs.chmodSync(path.join(payload, 'packaging/scripts/upgrade.sh'), 0o555)
  fs.chmodSync(path.join(payload, 'packaging/systemd/cdnca-edge-agent-root.service'), 0o555)
  assert.throws(() => createNativeNodeManifest(payload, metadata), /required member: packaging\/systemd/)
  fs.chmodSync(path.join(payload, 'packaging/systemd/cdnca-edge-agent-root.service'), 0o444)
  fs.writeFileSync(path.join(payload, 'packaging/scripts/extra.sh'), '#!/bin/sh\n', { mode: 0o555 })
  assert.throws(() => createNativeNodeManifest(payload, metadata), /unexpected package member/)
})

test('required Lua and service files are read-only data, never executables', (t) => {
  const { payload } = fixture(t)
  for (const name of required.filter((entry) => entry.startsWith('lua/') || entry.startsWith('evidence/'))) {
    fs.chmodSync(path.join(payload, name), 0o555)
    assert.throws(() => createNativeNodeManifest(payload, metadata), /required/)
    fs.chmodSync(path.join(payload, name), 0o444)
  }
})

test('finalization requires a valid external signature and refuses changed payloads', (t) => {
  const { directory, payload } = fixture(t)
  const manifest = createNativeNodeManifest(payload, metadata)
  const raw = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  fs.writeFileSync(path.join(directory, 'release.manifest.json'), raw)
  const signature = sign(null, Buffer.concat([Buffer.from('cdnca.native-node.release/v1\n'), raw]), privateKey)
  const signaturePath = path.join(directory, 'signature'), publicKeyPath = path.join(directory, 'public.pem')
  fs.writeFileSync(signaturePath, signature.toString('base64') + '\n')
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))
  const options = { buildDir: directory, signaturePath, publicKeyPath }
  fs.writeFileSync(signaturePath, Buffer.alloc(64).toString('base64') + '\n')
  assert.throws(() => finalizeNativeNodePackage(options), /signature/)
  fs.writeFileSync(signaturePath, signature.toString('base64') + '\n')
  // fixture() 只写 required 成员；签名后改动一个只受清单哈希约束的成员（原 evidence/cdnca-openresty-native.service 已随 native-unit-fix 删除）。
  const member = path.join(payload, 'lua/share/cdnca/range/guard.lua')
  fs.chmodSync(member, 0o644)
  fs.writeFileSync(member, 'changed after signing\n')
  fs.chmodSync(member, 0o444)
  assert.throws(() => finalizeNativeNodePackage(options), /changed/)
})

test('valid external signature creates a deterministic complete USTAR package once', (t) => {
  const { directory, payload } = fixture(t), manifest = createNativeNodeManifest(payload, metadata)
  const raw = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  fs.writeFileSync(path.join(directory, 'release.manifest.json'), raw)
  const signaturePath = path.join(directory, 'signature'), publicKeyPath = path.join(directory, 'public.pem')
  fs.writeFileSync(signaturePath, sign(null, Buffer.concat([Buffer.from('cdnca.native-node.release/v1\n'), raw]), privateKey).toString('base64') + '\n')
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))
  const result = finalizeNativeNodePackage({ buildDir: directory, signaturePath, publicKeyPath })
  assert.match(result.sha256, /^[0-9a-f]{64}$/)
  const archive = path.join(directory, 'cdnca-edge-agent.tar.gz')
  const names = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' }).trim().split('\n')
  assert.deepEqual(names, ['release.manifest.json', 'release.manifest.sig', ...required.sort()])
  assert.equal(gunzipSync(fs.readFileSync(archive)).subarray(257, 262).toString(), 'ustar')
  const second = path.join(directory, 'second-build')
  fs.mkdirSync(second)
  fs.cpSync(payload, path.join(second, 'payload'), { recursive: true })
  fs.writeFileSync(path.join(second, 'release.manifest.json'), raw)
  const secondResult = finalizeNativeNodePackage({ buildDir: second, signaturePath, publicKeyPath })
  assert.equal(secondResult.sha256, result.sha256)
  assert.throws(() => finalizeNativeNodePackage({ buildDir: directory, signaturePath, publicKeyPath }), /already exists/)
})
