import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import childProcess from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { test } from 'node:test'
import { copyNativeClickHouse, createNativeManifest } from './native-release-package.mjs'
import { createNativeControlInstallManifest, prepareNativeControlInstallPackage, finalizeNativeControlInstallPackage, verifyNativeControlInstallBundle } from './native-control-install-package.mjs'
import { finalizeNativeReleaseSignature } from './native-release-signature.mjs'

const repository = path.resolve(import.meta.dirname, '..')
const realExec = childProcess.execFileSync
const hash = (data) => createHash('sha256').update(data).digest('hex')
const encode = (value) => JSON.stringify(value, null, 2) + '\n'
const git = (cwd, args, options = {}) => realExec('git', ['--no-replace-objects', '-c', 'gc.auto=0', ...args], {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options,
}).trim()
const helpers = [
  'scripts/install-node.sh',
  'scripts/native-runtime/install-ubuntu-dependencies.sh', 'scripts/native-runtime/configure-clickhouse.py',
  'scripts/native-runtime/configure-nats.py', 'scripts/native-runtime/native-nats-profile.json',
  'scripts/native-runtime/install-rustfs.py', 'scripts/native-runtime/rustfs-1.0.1.json',
  'scripts/native-runtime/install-native-baseline.py', 'scripts/native-runtime/configure-control-runtime.py',
  'scripts/native-runtime/configure-certificate-runtime.py',
  'scripts/native-runtime/configure-native-upgrade.py', 'deploy/systemd/install-native-control-upgrade-runner.sh',
]
const sql = fs.readdirSync(path.join(repository, 'infra/clickhouse/migrations')).filter((name) => name.endsWith('.up.sql')).sort()
  .map((name) => `infra/clickhouse/migrations/${name}`)
const expectedPaths = ['native-management.tar', 'release.manifest.json', 'control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server', 'NATS-LICENSE', 'cdnca-ed25519', 'source.bundle', ...helpers, ...sql].sort()
// Mocked builds emit a host-native build of the real tool (so the embedded
// installer verifier can execute it); the committed fixture installer pins it.
const toolFixture = (() => {
  const output = path.join(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-ed25519-fixture-')), 'cdnca-ed25519')
  const env = { ...process.env, GOWORK: 'off', CGO_ENABLED: '0' }
  for (const name of ['GOFLAGS', 'GOEXPERIMENT', 'GOOS', 'GOARCH']) delete env[name]
  realExec('go', ['build', '-trimpath', '-o', output, '.'], { cwd: path.join(repository, 'tools/ed25519-tool'), env, stdio: ['ignore', 'pipe', 'pipe'] })
  return fs.readFileSync(output)
})()
const realToolPin = /^readonly CDNCA_ED25519_TOOL_SHA256="([a-f0-9]{64})"$/m.exec(fs.readFileSync(path.join(repository, 'scripts/install-node.sh'), 'utf8'))[1]

function nativeControlInstallFixture(t, realGo = false, sourceFault = '', signed = false, baseline = false) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-control-install-package-test-')))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const repo = path.join(directory, 'repo'), initial = path.join(directory, 'initial'), release = path.join(directory, 'release')
  const natsBuildDir = path.join(directory, 'nats-build'), elf = Buffer.alloc(128), license = Buffer.from('NATS test license\n')
  for (const folder of [repo, initial, release, natsBuildDir]) fs.mkdirSync(folder)
  elf.write('\x7fELF', 0, 'binary'); elf[4] = 2; elf[5] = 1; elf[6] = 1
  elf.writeUInt16LE(2, 16); elf.writeUInt16LE(62, 18)
  fs.writeFileSync(path.join(natsBuildDir, 'nats-server-2.12.15-cdnca.1'), elf, { mode: 0o755 })
  fs.writeFileSync(path.join(natsBuildDir, 'NATS-LICENSE'), license)
  if (realGo) {
    // Every local module control-api replaces must be in the archive, or the real Go build cannot load the module graph.
    const replaced = [...fs.readFileSync(path.join(repository, 'services/control-api/go.mod'), 'utf8')
      .matchAll(/^replace \S+ => \.\.\/\.\.\/(\S+)$/gm)].map((match) => match[1])
    git(repository, ['archive', '--format=tar', `--output=${path.join(directory, 'source.tar')}`, 'HEAD', '--',
      'services/control-api', ...new Set(replaced)])
    realExec('tar', ['-xf', path.join(directory, 'source.tar'), '-C', repo])
    // The working tree (not yet committed) supplies the tool exactly as built for the pin.
    for (const name of ['go.mod', 'main.go', 'build.sh']) {
      fs.mkdirSync(path.join(repo, 'tools/ed25519-tool'), { recursive: true })
      fs.copyFileSync(path.join(repository, 'tools/ed25519-tool', name), path.join(repo, 'tools/ed25519-tool', name))
    }
  }
  for (const name of [...helpers, ...sql, 'services/control-api/go.mod', 'services/control-api/cmd/.fixture', ...(realGo ? [] : ['tools/ed25519-tool/build.sh'])]) {
    if (realGo && name.endsWith('go.mod')) continue
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true })
    const pin = name === helpers[0] ? `readonly CDNCA_ED25519_TOOL_SHA256="${realGo ? realToolPin : hash(toolFixture)}"\n` : ''
    fs.writeFileSync(path.join(repo, name), `committed fixture: ${name}\n${pin}`, { mode: name.endsWith('.sh') ? 0o755 : 0o644 })
  }
  if (!realGo) {
    fs.mkdirSync(path.join(repo, 'services/control-api/migrations'), { recursive: true })
    for (const direction of ['up', 'down']) fs.writeFileSync(path.join(repo, `services/control-api/migrations/001_fixture.${direction}.sql`), 'fixture\n')
  }
  fs.writeFileSync(path.join(repo, 'scripts/native-runtime/native-nats-profile.json'), encode({
    server_version: '2.12.15-cdnca.1', server_artifact: { sha256: hash(elf), bytes: elf.length,
      license_sha256: hash(license), license_bytes: license.length },
  }))
  if (['missing', 'symlink'].includes(sourceFault)) {
    fs.unlinkSync(path.join(repo, helpers[0]))
    if (sourceFault === 'symlink') fs.symlinkSync('native-runtime/configure-nats.py', path.join(repo, helpers[0]))
  }
  if (sourceFault.startsWith('export-')) {
    fs.writeFileSync(path.join(repo, '.gitattributes'), `${helpers[0]} ${sourceFault}\n`)
    fs.appendFileSync(path.join(repo, helpers[0]), '$Format:%H$\n')
  }
  git(repo, ['init', '--quiet', '--template='])
  git(repo, ['add', '--', 'scripts', 'deploy', 'infra', 'services', 'tools', ...(realGo ? ['libs', 'proto'] : []), ...(sourceFault.startsWith('export-') ? ['.gitattributes'] : [])])
  git(repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'published predecessor'])
  const previous = git(repo, ['rev-parse', 'HEAD'])
  fs.writeFileSync(path.join(repo, 'candidate.txt'), 'candidate\n')
  git(repo, ['add', '--', 'candidate.txt'])
  git(repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'candidate'])
  git(repo, ['branch', '-M', 'main'])
  const commit = git(repo, ['rev-parse', 'HEAD']), tree = git(repo, ['rev-parse', 'HEAD^{tree}'])
  const unrelated = git(repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', tree, '-m', 'unrelated root'])
  git(repo, ['update-ref', 'refs/heads/unrelated', unrelated])
  const remote = path.join(directory, 'remote.git')
  git(directory, ['clone', '--quiet', '--bare', '--no-hardlinks', repo, remote])
  git(repo, ['remote', 'add', 'origin', remote])
  for (const name of ['bin/control-api', 'bin/agent-gateway', 'static/web/index.html']) {
    fs.mkdirSync(path.dirname(path.join(release, name)), { recursive: true })
    fs.writeFileSync(path.join(release, name), name.startsWith('bin/') ? elf : 'fixture\n', { mode: name.startsWith('bin/') ? 0o755 : 0o644 })
  }
  fs.mkdirSync(path.join(release, 'migrations'))
  for (const name of fs.readdirSync(path.join(repo, 'services/control-api/migrations')).filter((name) => /^[0-9]{3}_[a-z0-9_]+\.(up|down)\.sql$/.test(name))) {
    fs.copyFileSync(path.join(repo, 'services/control-api/migrations', name), path.join(release, 'migrations', name))
    fs.chmodSync(path.join(release, 'migrations', name), 0o644)
  }
  copyNativeClickHouse(repo, release)
  if (sourceFault === 'stale clickhouse') fs.appendFileSync(path.join(release, 'clickhouse/migrations', path.basename(sql.at(-1))), '-- not the source\n')
  for (const name of fs.readdirSync(path.join(release, 'clickhouse'), { recursive: true })) {
    if (fs.lstatSync(path.join(release, 'clickhouse', name)).isFile()) fs.chmodSync(path.join(release, 'clickhouse', name), 0o644)
  }
  const source = baseline ? { commit, tree } : { commit, tree, previous_commit: previous }, platform = { os: 'linux', arch: 'amd64' }
  const inner = createNativeManifest(release, { version: '1.0.3', built_at: '2026-10-08T00:00:00Z', source, platform, ...(signed ? { key_id: 'fixture-key' } : {}) })
  fs.writeFileSync(path.join(release, 'release.manifest.json'), encode(inner))
  const artifactKeys = generateKeyPairSync('ed25519'), artifactPublicKeyPath = path.join(directory, 'artifact-public.pem')
  if (signed) {
    fs.writeFileSync(artifactPublicKeyPath, artifactKeys.publicKey.export({ type: 'spki', format: 'pem' }))
    fs.writeFileSync(path.join(release, 'release.manifest.sig'), sign(null, Buffer.from(inner.schema + '\n' + encode(inner)), artifactKeys.privateKey).toString('base64') + '\n')
    fs.copyFileSync(path.join(release, 'release.manifest.sig'), path.join(initial, 'release.manifest.sig'))
  }
  fs.writeFileSync(path.join(directory, 'members'), ['release.manifest.json', ...(signed ? ['release.manifest.sig'] : []), ...inner.files.map((file) => file.path)].join('\n') + '\n')
  realExec('tar', ['--format=ustar', '-cf', path.join(initial, 'native-management.tar'), '-T', path.join(directory, 'members')], { cwd: release })
  fs.copyFileSync(path.join(release, 'release.manifest.json'), path.join(initial, 'release.manifest.json'))
  fs.writeFileSync(path.join(initial, 'control-upgrade-runner'), elf, { mode: 0o755 })
  if (realGo) {
    const env = { ...process.env, GOWORK: 'off', GOENV: 'off', GOOS: 'linux', GOARCH: 'amd64', GOAMD64: 'v1', CGO_ENABLED: '0' }
    delete env.GOFLAGS; delete env.GOEXPERIMENT
    realExec('go', ['build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-ldflags=-s -w', '-o', path.join(initial, 'control-upgrade-runner'), './cmd/control-upgrade-runner'],
      { cwd: path.join(repo, 'services/control-api'), env, stdio: ['ignore', 'pipe', 'pipe'] })
  }
  const compiledRunner = fs.readFileSync(path.join(initial, 'control-upgrade-runner'))
  const archive = fs.readFileSync(path.join(initial, 'native-management.tar'))
  const build = { schema: signed ? 'cdnca.native-management.signed-build/v2' : 'cdnca.native-management.unsigned-build/v1', installation_mode: 'first-native-baseline',
    previous_source_semantics: baseline ? 'initial-baseline-no-predecessor' : 'release-lineage-not-host-deployment', source, version: inner.version, built_at: inner.built_at,
    file: 'native-management.tar', sha256: hash(archive), bytes: archive.length, signing_required: !signed,
    runner: { file: 'control-upgrade-runner', sha256: hash(compiledRunner), bytes: compiledRunner.length, source: { commit, tree }, platform,
      version: inner.version, signing_required: true },
    ...(baseline ? { schema_gate: { control_schema_head: 1 } } : {}) }
  fs.writeFileSync(path.join(initial, 'build.json'), encode(build))
  // The working tree is deliberately dirty; only the pushed commit may supply helpers.
  if (!sourceFault) fs.writeFileSync(path.join(repo, helpers[0]), 'dirty helper must never ship\n')
  return { directory, repo, remote, initial, inner, build, commit, tree, previous, unrelated, realGo, artifactKeys, compiledRunner,
    options: { commit, remoteRef: 'refs/heads/main', initialBuildDir: initial, natsBuildDir, keyID: 'fixture-key', outputDir: path.join(directory, 'unsigned'),
      ...(signed ? { artifactPublicKeyPath } : {}) } }
}

function withNativeControlInstallCommands(t, fixture, mutate = {}) {
  const calls = []
  const mock = t.mock.method(childProcess, 'execFileSync', (command, args, options) => {
    calls.push({ command, args, options })
    if (command === 'git' && options.cwd === repository) options = { ...options, cwd: fixture.repo }
    mutate.before?.(command, args, options)
    if (command === 'sh' && args[0]?.endsWith('/tools/ed25519-tool/build.sh') && !fixture.realGo) {
      fs.writeFileSync(args[1], toolFixture)
      return ''
    }
    if (command === 'go' && !fixture.realGo) {
      if (args[0] === 'build') {
        fs.writeFileSync(args[args.indexOf('-o') + 1], fixture.compiledRunner)
        return ''
      }
      return JSON.stringify(fixture.inner) + '\n'
    }
    return realExec(command, args, options)
  })
  syncBuiltinESMExports()
  t.after(() => { mock.mock.restore(); syncBuiltinESMExports() })
  return calls
}

function signNativeControlInstallManifest(fixture, domain) {
  const { privateKey, publicKey } = fixture.options.artifactPublicKeyPath ? fixture.artifactKeys : generateKeyPairSync('ed25519')
  const signaturePath = path.join(fixture.directory, 'signature'), publicKeyPath = path.join(fixture.directory, 'public.pem')
  const raw = fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json'))
  domain ??= JSON.parse(raw).schema + '\n'
  fs.writeFileSync(signaturePath, sign(null, Buffer.concat([Buffer.from(domain), raw]), privateKey).toString('base64') + '\n')
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))
  return { buildDir: fixture.options.outputDir, remoteRef: fixture.options.remoteRef, signaturePath, publicKeyPath,
    ...(fixture.options.artifactPublicKeyPath ? { artifactPublicKeyPath: fixture.options.artifactPublicKeyPath } : {}) }
}

function nativeControlInstallArchiveMembers(encoded) {
  const result = new Map()
  let offset = 0
  while (encoded.subarray(offset, offset + 512).some((byte) => byte !== 0)) {
    const header = encoded.subarray(offset, offset + 512)
    assert.equal(header.length, 512)
    const text = (start, size) => header.subarray(start, start + size).toString().split('\0')[0]
    const octal = (start, size) => Number.parseInt(text(start, size).trim(), 8)
    assert.equal(text(257, 6), 'ustar'); assert.equal(text(156, 1), '0'); assert.equal(text(157, 100), '')
    assert.equal(octal(108, 8), 0); assert.equal(octal(116, 8), 0); assert.equal(octal(136, 12), 0)
    assert.equal(octal(148, 8), header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0))
    const name = [text(345, 155), text(0, 100)].filter(Boolean).join('/'), bytes = octal(124, 12)
    assert.equal(result.has(name), false)
    result.set(name, { bytes, mode: octal(100, 8), body: encoded.subarray(offset + 512, offset + 512 + bytes) })
    offset += 512 + Math.ceil(bytes / 512) * 512
  }
  assert.ok(encoded.length - offset >= 1024)
  assert.ok(encoded.subarray(offset).every((byte) => byte === 0))
  return result
}

test('prepare uses only pushed source, exact 37 payload files and a standalone HEAD-only bundle', (t) => {
  const fixture = nativeControlInstallFixture(t), calls = withNativeControlInstallCommands(t, fixture)
  const result = prepareNativeControlInstallPackage(fixture.options), output = fixture.options.outputDir
  assert.equal(result.signing_required, true)
  assert.equal(result.distribution, 'private-ssh-test-only')
  assert.equal(JSON.parse(fs.readFileSync(path.join(output, 'build.json'))).distribution, 'private-ssh-test-only')
  const raw = fs.readFileSync(path.join(output, 'install.manifest.json')), manifest = JSON.parse(raw)
  assert.deepEqual(Object.keys(manifest), ['schema', 'key_id', 'version', 'built_at', 'source', 'platform', 'files'])
  assert.equal(manifest.schema, 'cdnca.native-management.install/v1')
  assert.deepEqual(manifest.source, fixture.inner.source)
  assert.deepEqual(manifest.files.map((file) => file.path), expectedPaths)
  assert.deepEqual(fs.readFileSync(path.join(output, 'install.signing-data')), Buffer.concat([Buffer.from(manifest.schema + '\n'), raw]))
  for (const file of manifest.files) {
    assert.deepEqual(Object.keys(file), ['path', 'bytes', 'mode', 'sha256'])
    assert.equal(file.mode, ['native-management.tar', 'source.bundle'].includes(file.path) ? 0o600 : file.path.endsWith('.sh') || ['control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server', 'cdnca-ed25519'].includes(file.path) ? 0o755 : 0o644)
    assert.equal(hash(fs.readFileSync(path.join(output, 'payload', file.path))), file.sha256)
  }
  assert.match(fs.readFileSync(path.join(output, 'payload', helpers[0]), 'utf8'), /^committed fixture:/)
  const bare = path.join(fixture.directory, 'independent.git')
  git(fixture.directory, ['init', '--quiet', '--bare', '--template=', bare])
  const bundle = path.join(output, 'payload/source.bundle')
  assert.equal(git(bare, ['bundle', 'list-heads', bundle]), `${fixture.commit} HEAD`)
  git(bare, ['bundle', 'verify', bundle]); git(bare, ['bundle', 'unbundle', bundle])
  git(bare, ['merge-base', '--is-ancestor', fixture.previous, fixture.commit])
  assert.throws(() => git(bare, ['cat-file', '-e', fixture.unrelated]))
  assert.equal(calls.filter(({ command, args }) => command === 'git' && args.includes('ls-remote')).length, 2)
  assert.ok(calls.some(({ command, args }) => command === 'go' && args.includes('-mod=readonly')))
})

test('v2 public installation verifies private source but never distributes a bundle or source repository', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true), calls = withNativeControlInstallCommands(t, fixture)
  const result = prepareNativeControlInstallPackage(fixture.options)
  assert.equal(result.distribution, 'public-signed-no-source')
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  assert.equal(manifest.schema, 'cdnca.native-management.install/v2')
  assert.equal(manifest.files.length, 20 + sql.length)
  assert.ok(manifest.files.some((file) => file.path === 'release.manifest.sig'))
  assert.ok(manifest.files.every((file) => !file.path.includes('source.bundle') && !file.path.includes('.git')))
  assert.ok(calls.some(({ command, args }) => command === 'git' && args.includes('fsck')))
  const finalized = finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture))
  assert.equal(finalized.schema, manifest.schema)
  const members = nativeControlInstallArchiveMembers(fs.readFileSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')))
  assert.ok(members.has('release.manifest.sig'))
  assert.equal(members.has('source.bundle'), false)
})

for (const failure of ['', 'schema gate', 'wrong signature', 'changed payload', 'source SQL mismatch', 'remote advances', 'archive changes after validation', 'tampered schema gate']) {
  test(`inner v2 finalization ${failure === 'schema gate' ? 'carries the registration schema gate facts' : failure || 'signs before computing the final archive digest'}`, (t) => {
    const fixture = nativeControlInstallFixture(t, failure === '', '', true), payload = path.join(fixture.initial, 'payload')
    // native-release-package.mjs writes these facts; register.mjs reads them from the signed build.json.
    const schemaGate = failure.endsWith('schema gate') ? { schema_gate: { control_schema_head: failure === 'tampered schema gate' ? 2 : 1, rollback_min_version: '1.0.2' } } : {}
    fs.cpSync(path.join(fixture.directory, 'release'), payload, { recursive: true })
    fs.unlinkSync(path.join(payload, 'release.manifest.sig'))
    const manifestPath = path.join(fixture.initial, 'release.manifest.json')
    if (failure === 'source SQL mismatch') {
      const file = fixture.inner.files.find((item) => item.path.startsWith('migrations/'))
      fs.appendFileSync(path.join(payload, file.path), 'not from source\n')
      const bytes = fs.readFileSync(path.join(payload, file.path)); file.sha256 = hash(bytes); file.bytes = bytes.length
      fs.writeFileSync(manifestPath, encode(fixture.inner)); fs.writeFileSync(path.join(payload, 'release.manifest.json'), encode(fixture.inner))
      fs.writeFileSync(path.join(fixture.initial, 'release.manifest.sig'), sign(null, Buffer.from(fixture.inner.schema + '\n' + encode(fixture.inner)), fixture.artifactKeys.privateKey).toString('base64') + '\n')
    }
    fs.writeFileSync(path.join(fixture.directory, 'unsigned-members'), ['release.manifest.json', ...fixture.inner.files.map((file) => file.path)].join('\n') + '\n')
    realExec('tar', ['--format=ustar', '-cf', path.join(fixture.initial, 'native-management.unsigned.tar'), '-T', path.join(fixture.directory, 'unsigned-members')], { cwd: payload })
    const unsigned = fs.readFileSync(path.join(fixture.initial, 'native-management.unsigned.tar'))
    fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode({ ...fixture.build, schema: 'cdnca.native-management.unsigned-build/v2',
      file: 'native-management.unsigned.tar', signing_required: true, sha256: hash(unsigned), bytes: unsigned.length, ...schemaGate }))
    const outputDir = path.join(fixture.directory, 'signed-inner')
    let stagedArchive
    withNativeControlInstallCommands(t, fixture, { before(command, args) {
      if (failure === 'remote advances' && command === 'go' && args[0] === 'run') git(fixture.remote, ['update-ref', 'refs/heads/main', fixture.previous])
      if (command === 'tar' && args.includes('-cf')) stagedArchive = args[args.indexOf('-cf') + 1]
      if (failure === 'archive changes after validation' && stagedArchive && command === 'git' && args.includes('ls-remote')) fs.appendFileSync(stagedArchive, 'late mutation')
    } })
    if (failure === 'wrong signature') fs.writeFileSync(path.join(fixture.initial, 'release.manifest.sig'), Buffer.alloc(64).toString('base64'))
    if (failure === 'changed payload') fs.appendFileSync(path.join(payload, 'static/web/index.html'), 'changed')
    const run = () => finalizeNativeReleaseSignature({ buildDir: fixture.initial, remoteRef: fixture.options.remoteRef, outputDir,
      signaturePath: path.join(fixture.initial, 'release.manifest.sig'), publicKeyPath: fixture.options.artifactPublicKeyPath })
    if (failure && failure !== 'schema gate') { assert.throws(run); assert.equal(fs.existsSync(path.join(outputDir, 'build.json')), false); return }
    const result = run(), archive = fs.readFileSync(path.join(outputDir, 'native-management.tar'))
    assert.equal(result.schema, 'cdnca.native-management.signed-build/v2')
    assert.equal(result.signing_required, false)
    assert.deepEqual(result.schema_gate, schemaGate.schema_gate)
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(outputDir, 'build.json'))).schema_gate, schemaGate.schema_gate)
    assert.equal(result.sha256, hash(archive)); assert.notEqual(result.sha256, hash(unsigned))
    const members = nativeControlInstallArchiveMembers(archive)
    assert.deepEqual([...members.keys()], ['release.manifest.json', 'release.manifest.sig', ...fixture.inner.files.map((file) => file.path)])
    assert.deepEqual(members.get('release.manifest.json').body, fs.readFileSync(manifestPath))
    assert.equal(members.get('release.manifest.sig').mode, 0o644)
    assert.deepEqual(fs.readdirSync(outputDir).sort(), ['build.json', 'control-upgrade-runner', 'native-management.tar', 'release.manifest.json', 'release.manifest.sig'])
    assert.throws(run, /exist/)
  })
}

test('outer finalization rejects archive mutation during the final remote-tip check', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true)
  let stagedArchive
  withNativeControlInstallCommands(t, fixture, { before(command, args) {
    if (command === 'tar' && args.includes('-cf')) stagedArchive = args[args.indexOf('-cf') + 1]
    if (stagedArchive && command === 'git' && args.includes('ls-remote')) fs.appendFileSync(stagedArchive, 'late mutation')
  } })
  prepareNativeControlInstallPackage(fixture.options)
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /changed/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'SHA256SUMS')), false)
})

for (const sourceFault of ['export-ignore', 'export-subst']) {
  test(`private Git verification rejects ${sourceFault} drift from actual tree blobs`, (t) => {
    const fixture = nativeControlInstallFixture(t, false, sourceFault)
    const work = path.join(fixture.directory, 'private-check'), bundle = path.join(fixture.directory, 'source.bundle')
    fs.mkdirSync(work)
    git(fixture.repo, ['bundle', 'create', bundle, 'HEAD']); fs.chmodSync(bundle, 0o600)
    assert.throws(() => verifyNativeControlInstallBundle(bundle, fixture.inner, work), /archive|source|ENOENT/)
  })
}

for (const failure of ['changed migration', 'missing migration', 'missing trust', 'wrong trust', 'changed signature']) {
  test(`v2 publisher refuses ${failure} before producing signing data`, (t) => {
    const fixture = nativeControlInstallFixture(t, false, '', true)
    withNativeControlInstallCommands(t, fixture)
    if (failure === 'changed migration') fixture.inner.files.find((file) => file.path.startsWith('migrations/')).sha256 = 'a'.repeat(64)
    if (failure === 'missing migration') fixture.inner.files = fixture.inner.files.filter((file) => !file.path.endsWith('.down.sql'))
    if (failure.includes('migration')) {
      fs.writeFileSync(path.join(fixture.initial, 'release.manifest.json'), encode(fixture.inner))
      fs.writeFileSync(path.join(fixture.initial, 'release.manifest.sig'), sign(null, Buffer.from(fixture.inner.schema + '\n' + encode(fixture.inner)), fixture.artifactKeys.privateKey).toString('base64') + '\n')
    }
    if (failure === 'missing trust') delete fixture.options.artifactPublicKeyPath
    if (failure === 'wrong trust') fs.writeFileSync(fixture.options.artifactPublicKeyPath, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }))
    if (failure === 'changed signature') fs.writeFileSync(path.join(fixture.initial, 'release.manifest.sig'), Buffer.alloc(64).toString('base64') + '\n')
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /migration|trust|signature/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

for (const name of ['nats-server-2.12.15-cdnca.1', 'NATS-LICENSE']) {
  test(`prepare rejects ${name} that differs from the pushed dependency pin`, (t) => {
    const fixture = nativeControlInstallFixture(t)
    withNativeControlInstallCommands(t, fixture)
    fs.appendFileSync(path.join(fixture.options.natsBuildDir, name), 'changed')
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /NATS dependency differs/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

test('resigning a different NATS binary cannot bypass its archived dependency pin', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), manifestPath = path.join(fixture.options.outputDir, 'install.manifest.json')
  fs.appendFileSync(path.join(payload, 'nats-server'), 'different binary')
  fs.writeFileSync(manifestPath, encode(createNativeControlInstallManifest(payload, JSON.parse(fs.readFileSync(manifestPath)))))
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /NATS dependency differs/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')), false)
})

test('the signed support includes the official analytics bootstrap built only from archived source', (t) => {
  const fixture = nativeControlInstallFixture(t), calls = withNativeControlInstallCommands(t, fixture)
  prepareNativeControlInstallPackage(fixture.options)
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  const binary = manifest.files.find((file) => file.path === 'analytics-history-bootstrap')
  assert.ok(binary, 'fresh startup needs the signed analytics generation bootstrap')
  assert.equal(binary.mode, 0o755)
  const build = calls.find(({ command, args }) => command === 'go' && args.includes('./cmd/analytics-history-bootstrap'))
  assert.ok(build)
  assert.notEqual(build.options.cwd, path.join(fixture.repo, 'services/control-api'))
  assert.equal(build.options.env.GOOS, 'linux'); assert.equal(build.options.env.GOARCH, 'amd64')
  assert.equal(build.options.env.CGO_ENABLED, '0')
})

test('changing both runner and self-reported build digest cannot bypass exact-source reproduction', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true)
  const altered = Buffer.concat([fixture.compiledRunner, Buffer.from('NOT FROM ADVERTISED SOURCE\n')])
  fs.writeFileSync(path.join(fixture.initial, 'control-upgrade-runner'), altered)
  fixture.build.runner.sha256 = hash(altered); fixture.build.runner.bytes = altered.length
  fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(fixture.build))
  withNativeControlInstallCommands(t, fixture)
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /runner.*source/)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
})

test('resigning a changed runner does not bypass exact-source reproduction at outer finalization', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), manifestPath = path.join(fixture.options.outputDir, 'install.manifest.json')
  fs.appendFileSync(path.join(payload, 'control-upgrade-runner'), 'not from source\n')
  fs.writeFileSync(manifestPath, encode(createNativeControlInstallManifest(payload, JSON.parse(fs.readFileSync(manifestPath)))))
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /runner.*source/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')), false)
})

test('manifest rejects every missing path, extras, links, modes and oversize inputs', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), metadata = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  for (const name of expectedPaths) {
    const filename = path.join(payload, name), data = fs.readFileSync(filename), mode = fs.statSync(filename).mode & 0o7777
    fs.unlinkSync(filename)
    assert.throws(() => createNativeControlInstallManifest(payload, metadata), /missing|inventory/)
    fs.writeFileSync(filename, data, { mode })
  }
  const extra = path.join(payload, 'unexpected')
  fs.writeFileSync(extra, 'extra'); assert.throws(() => createNativeControlInstallManifest(payload, metadata), /inventory|unexpected/); fs.unlinkSync(extra)
  const filename = path.join(payload, helpers[0]), data = fs.readFileSync(filename)
  fs.chmodSync(filename, 0o777); assert.throws(() => createNativeControlInstallManifest(payload, metadata), /mode/)
  fs.chmodSync(filename, 0o755); fs.linkSync(filename, path.join(fixture.directory, 'hardlink'))
  assert.throws(() => createNativeControlInstallManifest(payload, metadata), /link|regular/); fs.unlinkSync(path.join(fixture.directory, 'hardlink'))
  fs.unlinkSync(filename); fs.symlinkSync(path.join(payload, helpers[1]), filename)
  assert.throws(() => createNativeControlInstallManifest(payload, metadata), /link|regular/)
  fs.unlinkSync(filename); fs.writeFileSync(filename, data, { mode: 0o755 })
  fs.truncateSync(filename, (8 << 20) + 1)
  assert.throws(() => createNativeControlInstallManifest(payload, metadata), /size|limit/)
})

for (const failure of ['wrong tip', 'wrong HEAD', 'self lineage', 'unrelated lineage', 'changed tar', 'changed runner', 'wrong ELF', 'missing helper', 'source symlink', 'remote advances']) {
  test(`prepare refuses ${failure} before a successful output`, (t) => {
    const fixture = nativeControlInstallFixture(t)
    if (failure === 'wrong tip') git(fixture.remote, ['update-ref', 'refs/heads/main', fixture.previous])
    if (failure === 'wrong HEAD') git(fixture.repo, ['update-ref', 'refs/heads/main', fixture.previous])
    if (failure.endsWith('lineage')) {
      fixture.build.source.previous_commit = failure === 'self lineage' ? fixture.commit : fixture.unrelated
      fixture.inner.source.previous_commit = fixture.build.source.previous_commit
      fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(fixture.build))
      fs.writeFileSync(path.join(fixture.initial, 'release.manifest.json'), encode(fixture.inner))
    }
    if (failure === 'changed tar') fs.appendFileSync(path.join(fixture.initial, 'native-management.tar'), 'changed')
    if (failure === 'changed runner') fs.appendFileSync(path.join(fixture.initial, 'control-upgrade-runner'), 'changed')
    if (failure === 'wrong ELF') {
      const runner = path.join(fixture.initial, 'control-upgrade-runner'), bytes = fs.readFileSync(runner)
      bytes.writeUInt16LE(183, 18); fs.writeFileSync(runner, bytes)
      fixture.build.runner.sha256 = hash(bytes); fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(fixture.build))
    }
    withNativeControlInstallCommands(t, fixture, { before(command, args, options) {
      if (command === 'go' && failure === 'remote advances') git(fixture.remote, ['update-ref', 'refs/heads/main', fixture.previous])
      if (command === 'go' && ['missing helper', 'source symlink'].includes(failure)) {
        const filename = path.join(options.cwd, '../../', helpers[0])
        fs.unlinkSync(filename)
        if (failure === 'source symlink') fs.symlinkSync(path.join(options.cwd, '../../', helpers[1]), filename)
      }
    } })
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options))
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

for (const signed of [false, true]) test(`finalize v${signed ? 2 : 1} validates external signatures and emits deterministic USTAR accepted by the embedded installer`, (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', signed)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const options = signNativeControlInstallManifest(fixture), result = finalizeNativeControlInstallPackage(options)
  const archive = fs.readFileSync(path.join(options.buildDir, 'cdnca-control-native.tar')), members = nativeControlInstallArchiveMembers(archive)
  const manifest = JSON.parse(fs.readFileSync(path.join(options.buildDir, 'install.manifest.json')))
  const paths = signed ? expectedPaths.filter((name) => name !== 'source.bundle').concat('release.manifest.sig').sort() : expectedPaths
  assert.deepEqual([...members.keys()], ['install.manifest.json', 'install.manifest.sig', ...paths])
  assert.equal(members.get('install.manifest.json').mode, 0o644); assert.equal(members.get('install.manifest.sig').mode, 0o644)
  for (const file of manifest.files) {
    assert.equal(members.get(file.path).mode, file.mode); assert.equal(members.get(file.path).bytes, file.bytes)
    assert.equal(hash(members.get(file.path).body), file.sha256)
  }
  assert.equal(hash(archive), result.sha256)
  assert.equal(fs.readFileSync(path.join(options.buildDir, 'SHA256SUMS'), 'utf8'), `${result.sha256}  cdnca-control-native.tar\n`)
  const installer = fs.readFileSync(path.join(repository, 'scripts/install-control.sh'), 'utf8')
    .match(/^verify_native_install_package\(\) \{[\s\S]*?^\}/m)?.[0]
  assert.ok(installer, 'the installed verifier must accept the actual builder output')
  const trust = path.join(fixture.directory, 'independent-trust.json')
  fs.writeFileSync(trust, JSON.stringify({ version: 1, keys: [{ key_id: 'fixture-key',
    public_key_pem: fs.readFileSync(options.publicKeyPath, 'utf8') }] }), { mode: 0o600 })
  const accepted = realExec('bash', ['-c', `set -euo pipefail\numask 077\nCDNCA_ED25519_TOOL_SHA256=${hash(toolFixture)}\n` +
    installer.replace('OWNER = 0', `OWNER = ${process.getuid()}`) + '\nverify_native_install_package "$1" "$2" "$3" "$4"',
  'fixture', path.join(options.buildDir, 'cdnca-control-native.tar'), trust, path.join(options.buildDir, 'accepted'),
  signed ? 'cdnca.native-management.install/v2' : ''],
  { encoding: 'utf8', timeout: 15000 })
  assert.deepEqual(JSON.parse(accepted).source, fixture.inner.source)
  assert.throws(() => finalizeNativeControlInstallPackage(options), /exist|overwrite/)
  const second = path.join(fixture.directory, 'second')
  fs.mkdirSync(second); fs.cpSync(path.join(options.buildDir, 'payload'), path.join(second, 'payload'), { recursive: true })
  fs.copyFileSync(path.join(options.buildDir, 'install.manifest.json'), path.join(second, 'install.manifest.json'))
  assert.equal(finalizeNativeControlInstallPackage({ ...options, buildDir: second }).sha256, result.sha256)
})

for (const failure of ['wrong domain', 'wrong key', 'bad encoding', 'changed payload', 'extra metadata', 'sidecar mismatch', 'all-refs bundle', 'remote advances']) {
  test(`finalize refuses ${failure} without publishing an archive`, (t) => {
    const fixture = nativeControlInstallFixture(t)
    withNativeControlInstallCommands(t, fixture, { before(command) {
      if (command === 'go' && failure === 'remote advances' && fs.existsSync(fixture.options.outputDir)) git(fixture.remote, ['update-ref', 'refs/heads/main', fixture.previous])
    } })
    prepareNativeControlInstallPackage(fixture.options)
    const manifestPath = path.join(fixture.options.outputDir, 'install.manifest.json'), payload = path.join(fixture.options.outputDir, 'payload')
    if (failure === 'extra metadata') {
      const value = JSON.parse(fs.readFileSync(manifestPath)); value.unexpected = true; fs.writeFileSync(manifestPath, encode(value))
    }
    if (failure === 'sidecar mismatch' || failure === 'all-refs bundle') {
      if (failure === 'sidecar mismatch') {
        const value = structuredClone(fixture.inner); value.built_at = '2026-10-09T00:00:00Z'
        fs.writeFileSync(path.join(payload, 'release.manifest.json'), encode(value))
      } else {
        fs.unlinkSync(path.join(payload, 'source.bundle'))
        git(fixture.repo, ['bundle', 'create', path.join(payload, 'source.bundle'), '--all'])
        fs.chmodSync(path.join(payload, 'source.bundle'), 0o600)
      }
      fs.writeFileSync(manifestPath, encode(createNativeControlInstallManifest(payload, JSON.parse(fs.readFileSync(manifestPath)))))
    }
    const options = signNativeControlInstallManifest(fixture, failure === 'wrong domain' ? 'wrong-domain\n' : undefined)
    if (failure === 'wrong key') fs.writeFileSync(options.publicKeyPath, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }))
    if (failure === 'bad encoding') fs.writeFileSync(options.signaturePath, 'not-base64')
    if (failure === 'changed payload') fs.appendFileSync(path.join(payload, helpers[0]), 'changed')
    assert.throws(() => finalizeNativeControlInstallPackage(options))
    assert.equal(fs.existsSync(path.join(options.buildDir, 'cdnca-control-native.tar')), false)
  })
}

for (const signed of [false, true]) test(`the real archived Go validator accepts a v${signed ? 2 : 1} baseline and rejects authenticated corrupt tar bytes`, (t) => {
  const fixture = nativeControlInstallFixture(t, true, '', signed)
  withNativeControlInstallCommands(t, fixture)
  prepareNativeControlInstallPackage(fixture.options)
  finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture))
  const candidate = fs.readFileSync(path.join(fixture.initial, 'native-management.tar'))
  candidate[0] ^= 1
  fs.writeFileSync(path.join(fixture.initial, 'native-management.tar'), candidate)
  fixture.build.sha256 = hash(candidate)
  fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(fixture.build))
  assert.throws(() => prepareNativeControlInstallPackage({ ...fixture.options, outputDir: path.join(fixture.directory, 'corrupt') }), /go|baseline|command/)
  assert.equal(fs.existsSync(path.join(fixture.directory, 'corrupt')), false)
})

test('a signed initial baseline without predecessor becomes a fresh-install package', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true, true)
  withNativeControlInstallCommands(t, fixture)
  const result = prepareNativeControlInstallPackage(fixture.options)
  assert.deepEqual(result.source, { commit: fixture.commit, tree: fixture.tree })
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  assert.deepEqual(manifest.source, { commit: fixture.commit, tree: fixture.tree })
  assert.deepEqual(finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)).source, manifest.source)
})

for (const [name, mutate] of [
  ['it claims chained lineage semantics', (build) => ({ ...build, previous_source_semantics: 'release-lineage-not-host-deployment' })],
  ['it has no schema gate', ({ schema_gate, ...build }) => build],
  ['it declares a rollback target', (build) => ({ ...build, schema_gate: { ...build.schema_gate, rollback_min_version: '1.0.2' } })],
  ['it is not a first-install build', ({ installation_mode, ...build }) => build],
]) {
  test(`an initial baseline without predecessor is rejected when ${name}`, (t) => {
    const fixture = nativeControlInstallFixture(t, false, '', true, true)
    withNativeControlInstallCommands(t, fixture)
    fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(mutate(fixture.build)))
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /provenance|lineage|invalid/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

// A signed release-chain inner build (native-release-package.mjs output after signing): no
// first-install markers and no runner; the outer prepare compiles the runner from the bundle.
function releaseChainBuild(fixture, mutate = (build) => build) {
  const { installation_mode, previous_source_semantics, runner, ...build } = fixture.build
  fs.unlinkSync(path.join(fixture.initial, 'control-upgrade-runner'))
  fs.writeFileSync(path.join(fixture.initial, 'build.json'), encode(mutate(build, fixture)))
}

test('signed release-chain inner package becomes the first-install identity with a source-built runner', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true)
  releaseChainBuild(fixture)
  const calls = withNativeControlInstallCommands(t, fixture)
  const result = prepareNativeControlInstallPackage(fixture.options)
  assert.equal(result.distribution, 'public-signed-no-source')
  const manifest = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  assert.deepEqual(manifest.source, fixture.inner.source)
  assert.equal(manifest.files.length, 20 + sql.length)
  const inner = manifest.files.find((file) => file.path === 'native-management.tar')
  assert.equal(inner.sha256, fixture.build.sha256)
  assert.equal(hash(fs.readFileSync(path.join(fixture.options.outputDir, 'payload/native-management.tar'))), fixture.build.sha256)
  assert.equal(manifest.files.find((file) => file.path === 'control-upgrade-runner').sha256, hash(fixture.compiledRunner))
  // Runner compiled for the payload and again for independent reproduction, both from the bundle checkout.
  const runnerBuilds = calls.filter(({ command, args }) => command === 'go' && args.includes('./cmd/control-upgrade-runner'))
  assert.equal(runnerBuilds.length, 2)
  assert.ok(runnerBuilds.every(({ args, options }) => args.includes('-mod=readonly') && options.env.GOWORK === 'off' &&
    !options.cwd.startsWith(fixture.repo)))
  assert.ok(calls.some(({ command, args }) => command === 'git' && args.includes('fsck')))
  const finalized = finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture))
  const members = nativeControlInstallArchiveMembers(fs.readFileSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')))
  assert.equal(hash(members.get('native-management.tar').body), fixture.build.sha256)
  assert.equal(finalized.source.previous_commit, fixture.previous)
})

for (const [name, mutate] of [
  ['unsigned', (build) => ({ ...build, schema: 'cdnca.native-management.unsigned-build/v1', signing_required: true })],
  ['half-marked', (build) => ({ ...build, previous_source_semantics: 'release-lineage-not-host-deployment' })],
  ['self-reported runner', (build, fixture) => ({ ...build, runner: fixture.build.runner })],
  ['unknown mode', (build) => ({ ...build, installation_mode: 'release-chain' })],
  ['changed digest', (build) => ({ ...build, sha256: 'f'.repeat(64) })],
  ['unrelated predecessor', (build, fixture) => ({ ...build, source: { ...build.source, previous_commit: fixture.unrelated } })],
]) {
  test(`release-chain inner package is rejected when ${name}`, (t) => {
    const fixture = nativeControlInstallFixture(t, false, '', true)
    releaseChainBuild(fixture, mutate)
    withNativeControlInstallCommands(t, fixture)
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options))
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

test('release-chain runner must still reproduce from the exact source bundle', (t) => {
  const fixture = nativeControlInstallFixture(t, false, '', true)
  releaseChainBuild(fixture)
  let runnerBuilds = 0
  withNativeControlInstallCommands(t, fixture, { before(command, args) {
    if (command === 'go' && args.includes('./cmd/control-upgrade-runner') && ++runnerBuilds === 2) {
      fixture.compiledRunner = Buffer.concat([fixture.compiledRunner, Buffer.from('second build differs\n')])
    }
  } })
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /runner.*source/)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
})

test('copied runner must still equal the initial builder digest before signing output is published', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture, { before(command, args) {
    if (command === 'git' && args.includes('bundle') && args.includes('create')) {
      const payload = path.dirname(args[args.indexOf('create') + 1])
      fs.appendFileSync(path.join(payload, 'control-upgrade-runner'), 'changed during staging')
    }
  } })
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /digest|changed/)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
})

test('each large-file cap and the total package cap reject sparse oversize files before hashing', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), metadata = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  for (const [name, limit] of [['native-management.tar', 285229182], ['control-upgrade-runner', 285229182], ['analytics-history-bootstrap', 285229182], ['source.bundle', 512 << 20]]) {
    const filename = path.join(payload, name), saved = fs.readFileSync(filename)
    fs.truncateSync(filename, limit + 1)
    assert.throws(() => createNativeControlInstallManifest(payload, metadata), /size limit/)
    fs.writeFileSync(filename, saved)
  }
  for (const [name, size] of [['native-management.tar', 285229182], ['control-upgrade-runner', 285229182], ['source.bundle', 512 << 20]]) {
    fs.truncateSync(path.join(payload, name), size)
  }
  assert.throws(() => createNativeControlInstallManifest(payload, metadata), /outer package exceeds size limit/)
})

test('existing output directories, dangling links and final publication races are never overwritten', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture, { before(command, args) {
    if (command === 'tar' && args.includes('--format=ustar') && fs.existsSync(fixture.options.outputDir)) {
      fs.writeFileSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar'), 'concurrent existing file')
    }
  } })
  fs.mkdirSync(fixture.options.outputDir)
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /exists/)
  fs.rmdirSync(fixture.options.outputDir)
  fs.symlinkSync(path.join(fixture.directory, 'absent'), fixture.options.outputDir)
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /exists/)
  assert.equal(fs.lstatSync(fixture.options.outputDir).isSymbolicLink(), true)
  fs.unlinkSync(fixture.options.outputDir)
  prepareNativeControlInstallPackage(fixture.options)
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /EEXIST|exists/)
  assert.equal(fs.readFileSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar'), 'utf8'), 'concurrent existing file')
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'SHA256SUMS')), false)
})

test('restrictive umask retains the exact signed payload and archive modes', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture)
  const previous = process.umask(0o077)
  try {
    prepareNativeControlInstallPackage(fixture.options)
    finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture))
  } finally { process.umask(previous) }
  const members = nativeControlInstallArchiveMembers(fs.readFileSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')))
  assert.equal(members.size, 22 + sql.length)
  assert.equal(members.get('install.manifest.json').mode, 0o644)
  assert.equal(members.get('scripts/install-node.sh').mode, 0o755)
  assert.equal(members.get('native-management.tar').mode, 0o600)
})

test('CLI rejects unknown, missing and duplicate arguments without creating output', () => {
  for (const args of [['unknown'], ['prepare', '--unknown', 'value'], ['prepare', '--source-commit'], ['finalize', '--remote-ref', 'one', '--remote-ref', 'two']]) {
    const result = childProcess.spawnSync(process.execPath, [path.join(repository, 'scripts/native-control-install-package.mjs'), ...args], { encoding: 'utf8' })
    assert.equal(result.status, 1); assert.equal(result.stdout, '')
    assert.match(result.stderr, /expected|unknown|missing|duplicate/)
  }
})

for (const sourceFault of ['missing', 'symlink']) {
  test(`pushed source ${sourceFault} cannot be rescued by a different working-tree helper`, (t) => {
    const fixture = nativeControlInstallFixture(t, false, sourceFault)
    withNativeControlInstallCommands(t, fixture)
    assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /ENOENT|source tree contains links/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

test('the release ClickHouse copy the upgrade runner applies must equal the archived source', (t) => {
  const fixture = nativeControlInstallFixture(t, false, 'stale clickhouse')
  withNativeControlInstallCommands(t, fixture)
  assert.throws(() => prepareNativeControlInstallPackage(fixture.options), /ClickHouse release file differs/)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
})

test('invalid install metadata fails closed without widening the fixed platform or lineage', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), metadata = JSON.parse(fs.readFileSync(path.join(fixture.options.outputDir, 'install.manifest.json')))
  for (const update of [{ version: 'development' }, { version: '01.0.3' }, { version: ['1.0.3'] }, { key_id: 'invalid key' }, { key_id: 123 }, { built_at: 'yesterday' },
    { platform: { os: 'linux', arch: 'arm64' } }, { source: { ...metadata.source, previous_commit: metadata.source.commit } }]) {
    assert.throws(() => createNativeControlInstallManifest(payload, { ...metadata, ...update }), /metadata/)
  }
})

test('validly signed helper bytes must still match the advertised source commit', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), manifestPath = path.join(fixture.options.outputDir, 'install.manifest.json')
  fs.appendFileSync(path.join(payload, helpers[0]), 'not in the commit\n')
  fs.writeFileSync(manifestPath, encode(createNativeControlInstallManifest(payload, JSON.parse(fs.readFileSync(manifestPath)))))
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /helper differs/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')), false)
})

test('validly signed analytics bootstrap bytes must still reproduce from the exact source bundle', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture); prepareNativeControlInstallPackage(fixture.options)
  const payload = path.join(fixture.options.outputDir, 'payload'), manifestPath = path.join(fixture.options.outputDir, 'install.manifest.json')
  fs.appendFileSync(path.join(payload, 'analytics-history-bootstrap'), 'not in the committed program\n')
  fs.writeFileSync(manifestPath, encode(createNativeControlInstallManifest(payload, JSON.parse(fs.readFileSync(manifestPath)))))
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /bootstrap differs/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')), false)
})

test('source replacement objects do not change the verified source tree or bundle lineage', (t) => {
  const fixture = nativeControlInstallFixture(t)
  git(fixture.repo, ['replace', fixture.previous, fixture.unrelated])
  withNativeControlInstallCommands(t, fixture)
  const result = prepareNativeControlInstallPackage(fixture.options)
  assert.deepEqual(result.source, fixture.inner.source)
  finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture))
})

test('finalization rechecks every staged payload byte after the Go validator returns', (t) => {
  const fixture = nativeControlInstallFixture(t)
  withNativeControlInstallCommands(t, fixture, { before(command, args) {
    if (command === 'go' && args[0] === 'run' && fs.existsSync(fixture.options.outputDir)) {
      const archive = args.find((value) => value.endsWith('/native-management.tar'))
      fs.appendFileSync(path.join(path.dirname(archive), 'control-upgrade-runner'), 'changed after validation')
    }
  } })
  prepareNativeControlInstallPackage(fixture.options)
  assert.throws(() => finalizeNativeControlInstallPackage(signNativeControlInstallManifest(fixture)), /changed/)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'cdnca-control-native.tar')), false)
})
