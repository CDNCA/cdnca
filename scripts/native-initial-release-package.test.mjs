import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { createHash } from 'node:crypto'
import { test } from 'node:test'
import childProcess from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { fileURLToPath } from 'node:url'
import { buildInitialNativeRelease } from './native-initial-release-package.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const predecessor = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'
const realExec = childProcess.execFileSync
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const git = (cwd, args) => realExec('git', ['--no-replace-objects', '-c', 'gc.auto=0', ...args], {
  cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
}).trim()

function initialReleaseFixture(t) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-initial-release-test-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const repo = path.join(root, 'repo'), remote = path.join(root, 'remote.git')
  fs.mkdirSync(repo)
  git(repo, ['init', '--quiet'])
  const common = git(repository, ['rev-parse', '--path-format=absolute', '--git-common-dir'])
  fs.writeFileSync(path.join(repo, '.git/objects/info/alternates'), path.join(common, 'objects') + '\n')
  const files = {
    'go.work': 'go 1.24\n',
    'apps/web/index.html': '<script src="/runtime-config.js"></script><main>committed entry</main>\n',
    'apps/web/public/runtime-config.js': '// installer serves its external public configuration\n',
    'scripts/install-node.sh': '#!/usr/bin/env bash\necho fixture node installer\n',
    'docs/runbooks/platform-admin-recovery.md': '# 主控平台管理员本地恢复\nfixture\n',
    'services/control-api/migrations/001_fixture.up.sql': 'SELECT 1;\n',
    'services/control-api/migrations/001_fixture.down.sql': 'SELECT 2;\n',
    'services/control-api/migrations/002_fixture.up.sql': 'SELECT 3;\n',
    'services/control-api/migrations/002_fixture.down.sql': 'SELECT 4;\n',
    'services/control-api/migrations/fixture_test.go': 'package migrations\n',
    'scripts/native-runtime/configure-clickhouse.py': '#!/usr/bin/env python3\n# fixture\n',
    'infra/clickhouse/migrations/001_fixture.up.sql': 'CREATE TABLE IF NOT EXISTS t1 (x UInt8) ENGINE = Memory;\n',
    'infra/clickhouse/migrations/001_fixture.down.sql': 'DROP TABLE IF EXISTS t1;\n',
  }
  for (const [name, contents] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(repo, name)), { recursive: true })
    fs.writeFileSync(path.join(repo, name), contents)
  }
  git(repo, ['add', '--', ...Object.keys(files)])
  const tree = git(repo, ['write-tree'])
  const commit = git(repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit-tree', tree, '-p', predecessor, '-m', 'initial baseline fixture'])
  git(repo, ['update-ref', 'refs/heads/main', commit])
  git(repo, ['symbolic-ref', 'HEAD', 'refs/heads/main'])
  git(root, ['init', '--quiet', '--bare', remote])
  fs.writeFileSync(path.join(remote, 'objects/info/alternates'), path.join(repo, '.git/objects') + '\n')
  git(remote, ['update-ref', 'refs/heads/main', commit])
  git(repo, ['remote', 'add', 'origin', remote])
  // A release must use committed archive bytes, not even this tracked dirty entry.
  fs.writeFileSync(path.join(repo, 'apps/web/index.html'), '<main>dirty, no runtime hook</main>')
  return { root, repo, remote, tree, commit, files,
    options: { commit, remoteRef: 'refs/heads/main', previousSourceCommit: predecessor,
      outputDir: path.join(root, 'output'), version: '1.0.3', arch: 'amd64', allowEmptySiteKey: true } }
}

function withInitialBuildCommands(t, fixture, mutate = {}) {
  const calls = [], work = new Set()
  const mock = t.mock.method(childProcess, 'execFileSync', (command, args, options) => {
    calls.push({ command, args, options })
    if (command === 'git') {
      assert.equal(args[0], '--no-replace-objects')
      return realExec(command, args, { ...options, cwd: fixture.repo })
    }
    if (command === 'go' || command === 'pnpm') {
      assert.notEqual(options.cwd, fixture.repo)
      const independentRunner = command === 'go' && args.at(-1) === './cmd/control-upgrade-runner'
      assert.equal(options.env.GOWORK, independentRunner ? 'off' : path.join(options.cwd, 'go.work'))
      assert.equal(options.env.GOENV, 'off')
      assert.equal(options.env.GOAMD64, 'v1')
      assert.equal(options.env.GOFLAGS, undefined)
      assert.equal(options.env.GOEXPERIMENT, undefined)
      if (independentRunner) {
        assert.ok(options.cwd.endsWith('/services/control-api'))
        assert.ok(args.includes('-mod=readonly'))
      }
      assert.equal(options.env.GOOS, 'linux')
      assert.equal(options.env.GOARCH, fixture.options.arch)
      assert.equal(options.env.CGO_ENABLED, '0')
      assert.equal(options.env.VITE_API_BASE_URL, '')
      assert.equal(options.env.VITE_PACKAGE_COMMERCE_ENABLED, 'true')
      assert.equal(options.env.VITE_RELEASE, fixture.options.commit)
      work.add(path.dirname(options.cwd))
      if (mutate.failBuild) throw new Error('fixture compiler failed')
      if (command === 'go') {
        const output = args[args.indexOf('-o') + 1], component = path.basename(output)
        assert.ok(args.includes('-trimpath'))
        assert.ok(args.includes('-buildvcs=false'))
        if (component === 'control-api') {
          const flags = args.find((arg) => arg.startsWith('-ldflags='))
          assert.ok(flags.includes(`main.controlSourceCommit=${fixture.options.commit}`))
          assert.ok(flags.includes(`main.controlSourceTree=${fixture.tree}`))
          assert.ok(flags.includes(`main.controlVersion=${fixture.options.version}`))
        }
        const bytes = Buffer.alloc(128)
        bytes.write('\x7fELF', 0, 'binary'); bytes[4] = 2; bytes[5] = 1; bytes[6] = 1
        bytes.writeUInt16LE(2, 16)
        bytes.writeUInt16LE(fixture.options.arch === 'amd64' ? 62 : 183, 18)
        bytes.write(component, 64)
        mutate.elf?.(bytes, component)
        fs.mkdirSync(path.dirname(output), { recursive: true })
        fs.writeFileSync(output, bytes)
        mutate.binary?.(output, component)
      } else if (args[0] === 'install') {
        assert.deepEqual(args, ['install', '--frozen-lockfile', '--filter', '@cdnca/web...'])
      } else {
        assert.deepEqual(args, ['--filter', '@cdnca/web', 'build'])
        const dist = path.join(options.cwd, 'apps/web/dist')
        fs.cpSync(path.join(options.cwd, 'apps/web/public'), dist, { recursive: true })
        fs.copyFileSync(path.join(options.cwd, 'apps/web/index.html'), path.join(dist, 'index.html'))
        fs.mkdirSync(path.join(dist, 'assets'))
        fs.writeFileSync(path.join(dist, 'assets/entry-abcdef.js'), 'export const committed = true;\n')
        mutate.web?.(dist)
        mutate.source?.(options.cwd)
        if (mutate.advanceRemote) git(fixture.remote, ['update-ref', 'refs/heads/main', predecessor])
      }
      return ''
    }
    assert.equal(command, 'tar')
    return realExec(command, args, options)
  })
  syncBuiltinESMExports()
  t.after(() => { mock.mock.restore(); syncBuiltinESMExports() })
  return { calls, work }
}

function initialArchiveMembers(buffer) {
  const members = new Map()
  let offset = 0
  while (buffer.subarray(offset, offset + 512).some((byte) => byte !== 0)) {
    const header = buffer.subarray(offset, offset + 512)
    assert.equal(header.length, 512)
    const string = (start, length) => header.subarray(start, start + length).toString().split('\0')[0]
    const octal = (start, length) => Number.parseInt(string(start, length).trim(), 8)
    assert.equal(string(257, 6), 'ustar')
    assert.equal(string(156, 1), '0', 'only ordinary regular file headers are permitted')
    assert.equal(string(157, 100), '')
    assert.equal(octal(108, 8), 0); assert.equal(octal(116, 8), 0)
    const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0)
    assert.equal(octal(148, 8), checksum)
    const name = [string(345, 155), string(0, 100)].filter(Boolean).join('/')
    assert.equal(members.has(name), false)
    const size = octal(124, 12)
    members.set(name, { mode: octal(100, 8), bytes: size, body: buffer.subarray(offset + 512, offset + 512 + size) })
    offset += 512 + Math.ceil(size / 512) * 512
  }
  assert.ok(buffer.length - offset >= 1024)
  assert.ok(buffer.subarray(offset).every((byte) => byte === 0))
  return members
}

for (const arch of ['amd64', 'arm64']) {
  test(`first ${arch} baseline is a complete ordinary tar from the exact committed tree with a separate runner`, (t) => {
    const fixture = initialReleaseFixture(t)
    fixture.options.arch = arch
    const { calls, work } = withInitialBuildCommands(t, fixture)
    const result = buildInitialNativeRelease(fixture.options)
    const output = fixture.options.outputDir
    assert.deepEqual(fs.readdirSync(output).sort(), ['build.json', 'control-upgrade-runner', 'native-management.tar', 'release.manifest.json'])
    assert.equal(result.schema, 'cdnca.native-management.unsigned-build/v1')
    assert.equal(result.installation_mode, 'first-native-baseline')
    assert.equal(result.previous_source_semantics, 'release-lineage-not-host-deployment')
    assert.equal(result.signing_required, true)
    assert.deepEqual(result.source, { commit: fixture.commit, tree: fixture.tree, previous_commit: predecessor })
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(output, 'build.json'))), result)
    const archive = fs.readFileSync(path.join(output, result.file))
    assert.equal(result.sha256, sha256(archive)); assert.equal(result.bytes, archive.length)
    const members = initialArchiveMembers(archive)
    const manifestBytes = fs.readFileSync(path.join(output, 'release.manifest.json'))
    assert.deepEqual(members.get('release.manifest.json').body, manifestBytes)
    assert.equal(members.get('release.manifest.json').mode, 0o644)
    const manifest = JSON.parse(manifestBytes)
    assert.equal(manifest.schema, 'cdnca.native-management.release/v1')
    assert.deepEqual(manifest.platform, { os: 'linux', arch })
    assert.deepEqual(manifest.source, result.source)
    assert.deepEqual([...members.keys()], ['release.manifest.json', ...manifest.files.map((file) => file.path)])
    assert.equal(manifest.files.filter((file) => file.path.startsWith('migrations/')).length, 4)
    assert.deepEqual(manifest.files.filter((file) => file.path.startsWith('clickhouse/')).map((file) => [file.path, file.mode]),
      [['clickhouse/configure-clickhouse.py', 0o644], ['clickhouse/migrations/001_fixture.up.sql', 0o644]])
    for (const file of manifest.files) {
      const member = members.get(file.path)
      assert.equal(member.mode, file.mode); assert.equal(member.bytes, file.bytes)
      assert.equal(sha256(member.body), file.sha256)
    }
    assert.equal(members.get('static/web/index.html').body.toString(), fixture.files['apps/web/index.html'])
    assert.equal(members.get('static/web/downloads/install-node.sh').body.toString(), fixture.files['scripts/install-node.sh'])
    assert.equal(members.get('static/web/downloads/install-node.sh').mode, 0o644)
    // 卡 41：root 恢复手册随包交付并由 manifest 纳管。
    assert.equal(members.get('docs/platform-admin-recovery.md').body.toString(), fixture.files['docs/runbooks/platform-admin-recovery.md'])
    assert.equal(members.get('docs/platform-admin-recovery.md').mode, 0o644)
    assert.equal(members.has('bin/control-upgrade-runner'), false)
    assert.deepEqual(result.runner.source, { commit: fixture.commit, tree: fixture.tree })
    assert.deepEqual(result.runner.platform, manifest.platform)
    assert.equal(result.runner.version, result.version)
    assert.equal(result.runner.signing_required, true)
    const runner = fs.readFileSync(path.join(output, result.runner.file))
    assert.equal(result.runner.sha256, sha256(runner)); assert.equal(result.runner.bytes, runner.length)
    assert.equal(fs.statSync(path.join(output, result.runner.file)).mode & 0o7777, 0o755)
    assert.equal(calls.filter(({ command, args }) => command === 'git' && args.includes('ls-remote')).length, 2)
    assert.equal(calls.filter(({ command }) => command === 'go').length, 3)
    assert.ok(calls.some(({ command, args }) => command === 'git' && args.includes('merge-base')))
    assert.ok(calls.some(({ command, args }) => command === 'git' && args.includes('archive') && args.at(-1) === fixture.commit))
    assert.ok([...work].every((directory) => !fs.existsSync(directory)))
  })
}

test('invalid arguments and unapproved or self lineage fail before any Git or compiler command', (t) => {
  const fixture = initialReleaseFixture(t), { calls } = withInitialBuildCommands(t, fixture)
  for (const patch of [{ previousSourceCommit: fixture.commit }, { previousSourceCommit: 'c'.repeat(40) },
    { previousSourceCommit: undefined }, { commit: predecessor }, { commit: 'HEAD' },
    { remoteRef: 'main' }, { version: '01.2.3' }, { version: '1.0.3-rc.1' }, { version: '1000000000.0.0' },
    { arch: '386' }, { outputDir: 'relative' }, { allowEmptySiteKey: false }]) {
    assert.throws(() => buildInitialNativeRelease({ ...fixture.options, ...patch }), /invalid|lineage/)
  }
  assert.equal(calls.length, 0)
})

test('v2 signing candidate retains only validated release payload and raw domain-separated signing bytes', (t) => {
  const fixture = initialReleaseFixture(t)
  withInitialBuildCommands(t, fixture)
  const result = buildInitialNativeRelease({ ...fixture.options, keyID: 'artifact-key-1' })
  assert.equal(result.schema, 'cdnca.native-management.unsigned-build/v2')
  assert.equal(result.file, 'native-management.unsigned.tar')
  assert.equal(result.signing_required, true)
  const raw = fs.readFileSync(path.join(fixture.options.outputDir, 'release.manifest.json'))
  const manifest = JSON.parse(raw)
  assert.equal(manifest.schema, 'cdnca.native-management.release/v2')
  assert.equal(manifest.key_id, 'artifact-key-1')
  assert.deepEqual(fs.readFileSync(path.join(fixture.options.outputDir, 'release.signing-data')),
    Buffer.concat([Buffer.from(manifest.schema + '\n'), raw]))
  assert.deepEqual(fs.readFileSync(path.join(fixture.options.outputDir, 'payload/release.manifest.json')), raw)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'native-management.tar')), false)
  assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'payload/source.bundle')), false)
})

test('existing directory and dangling output symlink are never overwritten', (t) => {
  const fixture = initialReleaseFixture(t), { calls } = withInitialBuildCommands(t, fixture)
  fs.mkdirSync(fixture.options.outputDir)
  assert.throws(() => buildInitialNativeRelease(fixture.options), /already exists/)
  fs.rmdirSync(fixture.options.outputDir)
  fs.symlinkSync(path.join(fixture.root, 'missing'), fixture.options.outputDir)
  assert.throws(() => buildInitialNativeRelease(fixture.options), /already exists/)
  assert.equal(calls.length, 0)
  assert.equal(fs.lstatSync(fixture.options.outputDir).isSymbolicLink(), true)
})

test('an exact remote tip not descended from the approved release is rejected by real Git', (t) => {
  const fixture = initialReleaseFixture(t)
  const orphan = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit-tree', fixture.tree, '-m', 'not descended from approved release'])
  git(fixture.remote, ['update-ref', 'refs/heads/main', orphan])
  fixture.options.commit = orphan
  const { calls } = withInitialBuildCommands(t, fixture)
  assert.throws(() => buildInitialNativeRelease(fixture.options))
  assert.equal(calls.some(({ command }) => command === 'go' || command === 'pnpm'), false)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
})

for (const advanceRemote of [false, true]) {
  test(`remote tip disagreement ${advanceRemote ? 'after' : 'before'} build publishes no output`, (t) => {
    const fixture = initialReleaseFixture(t)
    if (!advanceRemote) git(fixture.remote, ['update-ref', 'refs/heads/main', predecessor])
    const { calls, work } = withInitialBuildCommands(t, fixture, { advanceRemote })
    assert.throws(() => buildInitialNativeRelease(fixture.options), /exact remote branch tip/)
    assert.equal(calls.some(({ command }) => command === 'go'), advanceRemote)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
    assert.ok([...work].every((directory) => !fs.existsSync(directory)))
  })
}

for (const component of ['control-api', 'agent-gateway', 'control-upgrade-runner']) {
  for (const invalid of ['magic', 'class', 'endian', 'type', 'machine']) {
    test(`${component} rejects wrong ELF ${invalid} before publishing`, (t) => {
      const fixture = initialReleaseFixture(t)
      withInitialBuildCommands(t, fixture, { elf(bytes, name) {
        if (name !== component) return
        if (invalid === 'magic') bytes[0] = 0
        if (invalid === 'class') bytes[4] = 1
        if (invalid === 'endian') bytes[5] = 2
        if (invalid === 'type') bytes.writeUInt16LE(1, 16)
        if (invalid === 'machine') bytes.writeUInt16LE(183, 18)
      } })
      assert.throws(() => buildInitialNativeRelease(fixture.options), /ELF/)
      assert.equal(fs.existsSync(fixture.options.outputDir), false)
    })
  }
}

for (const invalid of ['symlink', 'hardlink', 'root-symlink', 'missing-hook', 'data-src', 'commented-hook', 'missing-runtime', 'unsafe-path']) {
  test(`built Web rejects ${invalid} without publishing`, (t) => {
    const fixture = initialReleaseFixture(t)
    withInitialBuildCommands(t, fixture, { web(dist) {
      if (invalid === 'symlink') fs.symlinkSync(path.join(dist, 'index.html'), path.join(dist, 'linked.html'))
      if (invalid === 'hardlink') fs.linkSync(path.join(dist, 'index.html'), path.join(dist, 'linked.html'))
      if (invalid === 'root-symlink') {
        fs.renameSync(dist, dist + '-real'); fs.symlinkSync(dist + '-real', dist)
      }
      if (invalid === 'missing-hook') fs.writeFileSync(path.join(dist, 'index.html'), '<main>missing hook</main>')
      if (invalid === 'data-src') fs.writeFileSync(path.join(dist, 'index.html'), '<script data-src="/runtime-config.js"></script>')
      if (invalid === 'commented-hook') fs.writeFileSync(path.join(dist, 'index.html'), '<!-- <script src="/runtime-config.js"></script> -->')
      if (invalid === 'missing-runtime') fs.unlinkSync(path.join(dist, 'runtime-config.js'))
      if (invalid === 'unsafe-path') fs.writeFileSync(path.join(dist, 'bad\npath'), 'unsafe')
    } })
    assert.throws(() => buildInitialNativeRelease(fixture.options), /regular|link|runtime-config|unsafe/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

for (const invalid of ['missing', 'unpaired', 'symlink', 'hardlink']) {
  test(`formal migration set rejects ${invalid} before publishing`, (t) => {
    const fixture = initialReleaseFixture(t)
    withInitialBuildCommands(t, fixture, { source(source) {
      const migrations = path.join(source, 'services/control-api/migrations')
      const file = path.join(migrations, '001_fixture.down.sql')
      if (invalid === 'missing') fs.rmSync(migrations, { recursive: true })
      else if (invalid === 'unpaired') fs.unlinkSync(file)
      else {
        fs.unlinkSync(file)
        if (invalid === 'symlink') fs.symlinkSync(path.join(migrations, '001_fixture.up.sql'), file)
        else fs.linkSync(path.join(migrations, '001_fixture.up.sql'), file)
      }
    } })
    assert.throws(() => buildInitialNativeRelease(fixture.options), /migration|regular|link|ENOENT/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

test('compiler failure removes only its temporary work, leaving no apparent successful build', (t) => {
  const fixture = initialReleaseFixture(t), { work } = withInitialBuildCommands(t, fixture, { failBuild: true })
  assert.throws(() => buildInitialNativeRelease(fixture.options), /fixture compiler failed/)
  assert.equal(fs.existsSync(fixture.options.outputDir), false)
  assert.ok([...work].every((directory) => !fs.existsSync(directory)))
  assert.ok(fs.existsSync(path.join(fixture.repo, '.git')))
})

test('a restrictive caller umask cannot produce an invalid native manifest header', (t) => {
  const fixture = initialReleaseFixture(t)
  withInitialBuildCommands(t, fixture)
  const previousMask = process.umask(0o077)
  let result
  try { result = buildInitialNativeRelease(fixture.options) } finally { process.umask(previousMask) }
  const members = initialArchiveMembers(fs.readFileSync(path.join(fixture.options.outputDir, result.file)))
  assert.equal(members.get('release.manifest.json').mode, 0o644)
  assert.ok([...members.values()].every(({ mode }) => mode === 0o644 || mode === 0o755))
})

test('Git replacement objects cannot rewrite the approved lineage or archived source tree', (t) => {
  const fixture = initialReleaseFixture(t)
  const replacement = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit-tree', fixture.tree, '-m', 'local fake predecessor'])
  git(fixture.repo, ['replace', predecessor, replacement])
  withInitialBuildCommands(t, fixture)
  const result = buildInitialNativeRelease(fixture.options)
  assert.deepEqual(result.source, { commit: fixture.commit, tree: fixture.tree, previous_commit: predecessor })
})

for (const invalid of ['symlink', 'hardlink', 'missing', 'truncated']) {
  test(`independent runner rejects ${invalid} compiler output`, (t) => {
    const fixture = initialReleaseFixture(t)
    withInitialBuildCommands(t, fixture, { binary(filename, component) {
      if (component !== 'control-upgrade-runner') return
      if (invalid === 'truncated') fs.truncateSync(filename, 32)
      else if (invalid === 'hardlink') fs.linkSync(filename, filename + '-linked')
      else {
        fs.unlinkSync(filename)
        if (invalid === 'symlink') fs.symlinkSync(path.join(fixture.repo, 'go.work'), filename)
      }
    } })
    assert.throws(() => buildInitialNativeRelease(fixture.options), /ELF|regular|link|ENOENT/)
    assert.equal(fs.existsSync(fixture.options.outputDir), false)
  })
}

test('CLI rejects unknown, missing and duplicate flags without building', () => {
  const script = path.join(repository, 'scripts/native-initial-release-package.mjs')
  for (const args of [['--unknown', 'value'], ['--source-commit'], ['--version', '1.0.0', '--version', '1.0.1']]) {
    const result = childProcess.spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' })
    assert.equal(result.status, 1)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /unknown, missing or duplicate argument/)
  }
})

test('--baseline builds an initial release with no predecessor, ancestry check or rollback target', (t) => {
  const fixture = initialReleaseFixture(t)
  // A baseline commit need not descend from any earlier release (1.0.35 is an initial version).
  const orphan = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
    'commit-tree', fixture.tree, '-m', 'initial baseline without lineage'])
  git(fixture.remote, ['update-ref', 'refs/heads/main', orphan])
  const { previousSourceCommit, ...options } = { ...fixture.options, commit: orphan, baseline: true, keyID: 'artifact-key-1' }
  fixture.options.commit = orphan
  const { calls } = withInitialBuildCommands(t, fixture)
  const result = buildInitialNativeRelease(options)
  assert.equal(previousSourceCommit, predecessor)
  assert.equal(result.installation_mode, 'first-native-baseline')
  assert.equal(result.previous_source_semantics, 'initial-baseline-no-predecessor')
  assert.deepEqual(result.source, { commit: orphan, tree: fixture.tree })
  assert.deepEqual(result.schema_gate, { control_schema_head: 2 })
  const raw = fs.readFileSync(path.join(options.outputDir, 'release.manifest.json'))
  assert.deepEqual(JSON.parse(raw).source, { commit: orphan, tree: fixture.tree })
  assert.deepEqual(fs.readFileSync(path.join(options.outputDir, 'release.signing-data')),
    Buffer.concat([Buffer.from('cdnca.native-management.release/v2\n'), raw]))
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(options.outputDir, 'build.json'))), result)
  assert.equal(calls.some(({ command, args }) => command === 'git' && (args.includes('merge-base') || args.includes(`${predecessor}^{tree}`))), false)
})

test('--baseline and a predecessor are mutually exclusive', (t) => {
  const fixture = initialReleaseFixture(t), { calls } = withInitialBuildCommands(t, fixture)
  for (const patch of [{ baseline: true }, { baseline: false }, { baseline: 'yes', previousSourceCommit: undefined }]) {
    assert.throws(() => buildInitialNativeRelease({ ...fixture.options, ...patch }), /invalid|lineage/)
  }
  assert.equal(calls.length, 0)
})
