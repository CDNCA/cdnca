import assert from 'node:assert/strict'
import fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { test } from 'node:test'
import childProcess from 'node:child_process'
import { syncBuiltinESMExports } from 'node:module'
import { createNativeManifest, assertAppendOnlyMigrations, assertAppendOnlyClickHouse, buildNativeRelease, copyNativeClickHouse, preserveNativeWebFiles, nativeSchemaGateFacts } from './native-release-package.mjs'

const metadata = { version: '2026.10.8', built_at: '2026-10-08T00:00:00Z',
  source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), previous_commit: 'c'.repeat(40) },
  platform: { os: 'linux', arch: 'amd64' } }

function fixture(t) {
  const root = fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-package-test-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  for (const file of ['bin/control-api', 'bin/agent-gateway', 'static/web/index.html', 'migrations/001_test.up.sql']) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true })
    fs.writeFileSync(path.join(root, file), `fixture:${file}`, { mode: file.startsWith('bin/') ? 0o755 : 0o644 })
  }
  return root
}

test('manifest records sorted exact content hashes and excludes itself', (t) => {
  const root = fixture(t)
  fs.writeFileSync(path.join(root, 'release.manifest.json'), '{}')
  const manifest = createNativeManifest(root, metadata)
  assert.equal(manifest.schema, 'cdnca.native-management.release/v1')
  assert.equal(manifest.files.length, 4)
  assert.deepEqual(manifest.files.map((file) => file.path), [...manifest.files.map((file) => file.path)].sort())
  assert.ok(manifest.files.every((file) => /^[a-f0-9]{64}$/.test(file.sha256)))
  assert.deepEqual(assertAppendOnlyMigrations(manifest, structuredClone(manifest)), [])
})

test('signed v2 manifest binds the key ID but keeps its detached signature outside files', (t) => {
  const root = fixture(t)
  fs.writeFileSync(path.join(root, 'release.manifest.sig'), 'detached-signature\n', { mode: 0o644 })
  const manifest = createNativeManifest(root, { ...metadata, key_id: 'artifact-key-1' })
  assert.equal(manifest.schema, 'cdnca.native-management.release/v2')
  assert.equal(manifest.key_id, 'artifact-key-1')
  assert.equal(manifest.files.length, 4)
  for (const key_id of ['', 'space key', 1, 'a'.repeat(129)]) {
    assert.throws(() => createNativeManifest(root, { ...metadata, key_id }), /metadata/)
  }
  assert.throws(() => createNativeManifest(root, metadata), /signature/)
})

test('manifest rejects links, missing components and unsafe modes', (t) => {
  const root = fixture(t)
  fs.symlinkSync('/etc/hosts', path.join(root, 'host-link'))
  assert.throws(() => createNativeManifest(root, metadata), /link/)
  fs.unlinkSync(path.join(root, 'host-link'))
  fs.chmodSync(path.join(root, 'bin/control-api'), 0o777)
  assert.throws(() => createNativeManifest(root, metadata), /mode/)
  fs.chmodSync(path.join(root, 'bin/control-api'), 0o755)
  fs.unlinkSync(path.join(root, 'bin/agent-gateway'))
  assert.throws(() => createNativeManifest(root, metadata), /required release file/)
})

test('manifest requires stable version, full source identity and supported platform', (t) => {
  const root = fixture(t)
  for (const patch of [{ version: 'development' }, { version: '01.2.3' }, { source: {} },
    { built_at: 'unknown' }, { built_at: '2026-10-08' }, { built_at: '2026-02-31T00:00:00Z' },
    { platform: { os: 'darwin', arch: 'arm64' } }]) {
    assert.throws(() => createNativeManifest(root, { ...metadata, ...patch }), /metadata/)
  }
})

test('manifest schema cannot be overridden and hard links are rejected', (t) => {
  const root = fixture(t)
  assert.equal(createNativeManifest(root, { ...metadata, schema: 'wrong' }).schema, 'cdnca.native-management.release/v1')
  fs.linkSync(path.join(root, 'bin/control-api'), path.join(root, 'linked-control'))
  assert.throws(() => createNativeManifest(root, metadata), /link/)
})

test('native migrations may only be appended with contiguous up/down pairs', (t) => {
  const manifest = createNativeManifest(fixture(t), metadata)
  const add = (files, name, extra = {}) => files.push({ path: `migrations/${name}`, sha256: 'd'.repeat(64), bytes: 9, mode: 0o644, ...extra })
  const sort = (files) => files.sort((a, b) => a.path < b.path ? -1 : 1)
  const appended = structuredClone(manifest)
  for (const name of ['002_node_delete.up.sql', '002_node_delete.down.sql', '003_node_audit.up.sql', '003_node_audit.down.sql']) add(appended.files, name)
  sort(appended.files)
  assert.deepEqual(assertAppendOnlyMigrations(manifest, appended), ['002_node_delete', '003_node_audit'])
  for (const [reason, mutate, error] of [
    ['changed', (files) => { files.find((file) => file.path.startsWith('migrations/')).sha256 = 'e'.repeat(64) }, /existing migration changed/],
    ['mode changed', (files) => { files.find((file) => file.path.startsWith('migrations/')).mode = 0o755 }, /existing migration changed/],
    ['removed', (files) => { files.splice(files.findIndex((file) => file.path.startsWith('migrations/001')), 1) }, /existing migration changed or removed/],
    ['missing down', (files) => { add(files, '002_new.up.sql') }, /matching up and down/],
    ['name mismatch', (files) => { add(files, '002_new.up.sql'); add(files, '002_other.down.sql') }, /matching up and down/],
    ['gap', (files) => { add(files, '003_new.up.sql'); add(files, '003_new.down.sql') }, /contiguous/],
    ['below head', (files) => { add(files, '001_extra.down.sql') }, /not after the current head/],
    ['bad name', (files) => { add(files, '002-new.up.sql') }, /invalid new migration/],
    ['empty', (files) => { add(files, '002_new.up.sql', { bytes: 0 }); add(files, '002_new.down.sql') }, /invalid new migration/],
    ['executable', (files) => { add(files, '002_new.up.sql', { mode: 0o755 }); add(files, '002_new.down.sql') }, /invalid new migration/],
  ]) {
    const next = structuredClone(manifest)
    mutate(next.files)
    assert.throws(() => assertAppendOnlyMigrations(manifest, next), error, reason)
  }
})

test('build fails closed before Git/network for invalid or incomplete arguments', () => {
  assert.throws(() => buildNativeRelease({}), /invalid build arguments/)
  assert.throws(() => buildNativeRelease({ commit: 'HEAD', remoteRef: 'main', version: '1.0.0', arch: 'amd64' }), /invalid build arguments/)
})

test('build rejects baseline root and ancestor symlinks before commands without changing the baseline', (t) => {
  const previous = fs.realpathSync(fixture(t)), aliases = fs.realpathSync(fixture(t))
  fs.writeFileSync(path.join(previous, 'release.manifest.json'), '{}')
  const before = createNativeManifest(previous, metadata)
  const command = t.mock.method(childProcess, 'execFileSync', () => { throw new Error('unexpected build command') })
  syncBuiltinESMExports()
  t.after(() => { command.mock.restore(); syncBuiltinESMExports() })
  fs.symlinkSync(previous, path.join(aliases, 'current'))
  fs.symlinkSync(path.dirname(previous), path.join(aliases, 'release-parent'))
  for (const previousRelease of [path.join(aliases, 'current'), path.join(aliases, 'release-parent', path.basename(previous))]) {
    assert.throws(() => buildNativeRelease({ commit: 'a'.repeat(40), remoteRef: 'refs/heads/main',
      version: '2026.10.9', arch: 'amd64', allowEmptySiteKey: true, previousRelease,
      outputDir: path.join(aliases, 'output') }), /previous release must be a canonical directory/)
  }
  assert.equal(command.mock.callCount(), 0)
  assert.deepEqual(createNativeManifest(previous, metadata), before)
  assert.equal(fs.readFileSync(path.join(previous, 'release.manifest.json'), 'utf8'), '{}')
})

test('build rejects output aliases into the immutable baseline before commands', (t) => {
  const previousRelease = fs.realpathSync(fixture(t)), aliases = fs.realpathSync(fixture(t))
  const command = t.mock.method(childProcess, 'execFileSync', () => { throw new Error('unexpected build command') })
  syncBuiltinESMExports()
  t.after(() => { command.mock.restore(); syncBuiltinESMExports() })
  fs.symlinkSync(previousRelease, path.join(aliases, 'output-parent'))
  fs.symlinkSync(path.join(previousRelease, 'static/web'), path.join(aliases, 'output-web'))
  const before = createNativeManifest(previousRelease, metadata)
  for (const outputDir of [path.join(previousRelease, 'output'), path.join(aliases, 'output-parent', 'output'),
    path.join(aliases, 'output-web', 'output')]) {
    assert.throws(() => buildNativeRelease({ commit: 'a'.repeat(40), remoteRef: 'refs/heads/main',
      version: '2026.10.9', arch: 'amd64', allowEmptySiteKey: true, previousRelease, outputDir }),
    /output directory must not modify the immutable previous release/)
  }
  assert.equal(command.mock.callCount(), 0)
  assert.equal(fs.existsSync(path.join(previousRelease, 'output')), false)
  assert.deepEqual(createNativeManifest(previousRelease, metadata), before)
})

for (const link of ['root', 'nested']) {
  test(`build rejects a ${link} symlink introduced during clone before replacing files`, (t) => {
    const previousRelease = fs.realpathSync(fixture(t)), outputParent = fs.realpathSync(fixture(t))
    const before = createNativeManifest(previousRelease, metadata), encoded = JSON.stringify(before)
    fs.writeFileSync(path.join(previousRelease, 'release.manifest.json'), encoded)
    const commit = 'd'.repeat(40), remoteRef = 'refs/heads/main', realCopy = fs.cpSync
    const command = t.mock.method(childProcess, 'execFileSync', (program, args) => {
      assert.equal(program, 'git')
      assert.equal(args[0], '--no-replace-objects')
      args = args.slice(1)
      if (args[0] === 'ls-remote') return `${commit}\t${remoteRef}`
      if (args[0] === 'merge-base') return ''
      if (args[0] === 'rev-parse') return metadata.source.tree
      throw new Error('unexpected build command')
    })
    const copy = t.mock.method(fs, 'cpSync', (source, target, options) => {
      if (link === 'root') return fs.symlinkSync(source, target)
      realCopy(source, target, options)
      fs.rmSync(path.join(target, 'static/web'), { recursive: true })
      fs.symlinkSync(path.join(source, 'static/web'), path.join(target, 'static/web'))
    })
    syncBuiltinESMExports()
    t.after(() => { copy.mock.restore(); command.mock.restore(); syncBuiltinESMExports() })
    assert.throws(() => buildNativeRelease({ commit, remoteRef, version: '2026.10.9', arch: 'amd64',
      allowEmptySiteKey: true, previousRelease, outputDir: path.join(outputParent, 'output') }),
    /copied baseline|release contains a link/)
    assert.equal(command.mock.callCount(), 3)
    assert.equal(copy.mock.callCount(), 1)
    assert.deepEqual(createNativeManifest(previousRelease, metadata), before)
    assert.equal(fs.readFileSync(path.join(previousRelease, 'release.manifest.json'), 'utf8'), encoded)
    assert.equal(fs.existsSync(path.join(outputParent, 'output')), false)
  })
}

test('build retains runtime configuration and old public paths without replacing the new entry', (t) => {
  const previous = fixture(t), candidate = fixture(t)
  fs.writeFileSync(path.join(previous, 'static/web/runtime-config.js'), 'window.runtimeConfig = {};')
  fs.writeFileSync(path.join(candidate, 'static/web/runtime-config.js'), '// unconfigured build default')
  fs.mkdirSync(path.join(previous, 'static/web/assets'))
  fs.writeFileSync(path.join(previous, 'static/web/assets/old-hash.js'), 'old hashed content')
  fs.writeFileSync(path.join(candidate, 'static/web/index.html'), 'new entry')
  const files = createNativeManifest(previous, metadata).files
  preserveNativeWebFiles(previous, candidate, files)
  assert.equal(fs.readFileSync(path.join(candidate, 'static/web/runtime-config.js'), 'utf8'), 'window.runtimeConfig = {};')
  assert.equal(fs.readFileSync(path.join(candidate, 'static/web/index.html'), 'utf8'), 'new entry')
  assert.equal(fs.readFileSync(path.join(candidate, 'static/web/assets/old-hash.js'), 'utf8'), 'old hashed content')
  fs.writeFileSync(path.join(candidate, 'static/web/assets/old-hash.js'), 'hash-name collision')
  assert.throws(() => preserveNativeWebFiles(previous, candidate, files), /immutable asset name collision/)
})

test('build refuses to silently disconnect an active runtime configuration script', (t) => {
  const previous = fixture(t), candidate = fixture(t)
  const script = '<script src="/runtime-config.js"></script>'
  fs.writeFileSync(path.join(previous, 'static/web/index.html'), `${script}<main>old</main>`)
  fs.writeFileSync(path.join(previous, 'static/web/runtime-config.js'), 'window.runtimeConfig = {};')
  const files = createNativeManifest(previous, metadata).files
  assert.throws(() => preserveNativeWebFiles(previous, candidate, files), /preserve the verified runtime-config integration/)
  fs.writeFileSync(path.join(candidate, 'static/web/index.html'), `${script}<main>new</main>`)
  preserveNativeWebFiles(previous, candidate, files)
})

// The ClickHouse inputs every release carries (helper + contiguous up migrations).
function writeClickHouseSource(repo, count = 2) {
  fs.mkdirSync(path.join(repo, 'infra/clickhouse/migrations'), { recursive: true })
  fs.mkdirSync(path.join(repo, 'scripts/native-runtime'), { recursive: true })
  fs.writeFileSync(path.join(repo, 'scripts/native-runtime/configure-clickhouse.py'), '#!/usr/bin/env python3\n# fixture\n')
  for (let version = 1; version <= count; version++) {
    const name = `${String(version).padStart(3, '0')}_fixture_${version}`
    fs.writeFileSync(path.join(repo, `infra/clickhouse/migrations/${name}.up.sql`), `CREATE TABLE IF NOT EXISTS t${version} (x UInt8) ENGINE = Memory;\n`)
    fs.writeFileSync(path.join(repo, `infra/clickhouse/migrations/${name}.down.sql`), `DROP TABLE IF EXISTS t${version};\n`)
  }
}

// A previous release that already serves an older node installer, plus a pushed candidate commit.
function chainedBuildFixture(t) {
  const previousRelease = fs.realpathSync(fixture(t)), parent = fs.realpathSync(fixture(t))
  const repo = path.join(parent, 'repo'), remote = path.join(parent, 'remote.git'), realExec = childProcess.execFileSync
  fs.mkdirSync(repo)
  fs.mkdirSync(path.join(previousRelease, 'static/web/downloads'))
  fs.writeFileSync(path.join(previousRelease, 'static/web/downloads/install-node.sh'), '#!/usr/bin/env bash\necho previous installer\n', { mode: 0o644 })
  const git = (args, options = {}) => realExec('git', args, { cwd: repo, encoding: 'utf8', ...options }).trim()
  git(['init', '--quiet', '--template='])
  fs.writeFileSync(path.join(repo, 'compiler-input.txt'), 'original source\n')
  fs.mkdirSync(path.join(repo, 'scripts'))
  fs.writeFileSync(path.join(repo, 'scripts/install-node.sh'), '#!/usr/bin/env bash\necho previous installer\n', { mode: 0o755 })
  fs.mkdirSync(path.join(repo, 'docs/runbooks'), { recursive: true })
  fs.writeFileSync(path.join(repo, 'docs/runbooks/platform-admin-recovery.md'), '# recovery previous\n')
  fs.mkdirSync(path.join(repo, 'services/control-api/migrations'), { recursive: true })
  fs.copyFileSync(path.join(previousRelease, 'migrations/001_test.up.sql'), path.join(repo, 'services/control-api/migrations/001_test.up.sql'))
  writeClickHouseSource(repo)
  git(['add', '--', 'compiler-input.txt', 'scripts', 'services', 'infra', 'docs'])
  const commitArgs = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet']
  git([...commitArgs, '-m', 'previous'])
  const previousCommit = git(['rev-parse', 'HEAD']), previousTree = git(['rev-parse', 'HEAD^{tree}'])
  fs.writeFileSync(path.join(previousRelease, 'release.manifest.json'), JSON.stringify(createNativeManifest(previousRelease, {
    ...metadata, source: { ...metadata.source, commit: previousCommit, tree: previousTree },
  })))
  fs.writeFileSync(path.join(repo, 'compiler-input.txt'), 'pushed source\n')
  fs.writeFileSync(path.join(repo, 'scripts/install-node.sh'), '#!/usr/bin/env bash\necho candidate installer\n')
  fs.writeFileSync(path.join(repo, 'docs/runbooks/platform-admin-recovery.md'), '# recovery candidate\n')
  git(['add', '--', 'compiler-input.txt', 'scripts', 'docs']); git([...commitArgs, '-m', 'candidate'])
  git(['branch', '-M', 'main'])
  const commit = git(['rev-parse', 'HEAD']), tree = git(['rev-parse', 'HEAD^{tree}'])
  git(['clone', '--quiet', '--bare', '--no-hardlinks', repo, remote]); git(['remote', 'add', 'origin', remote])
  const webEnv = []
  const command = t.mock.method(childProcess, 'execFileSync', (program, args, options) => {
    if (program === 'git') return realExec(program, args, { ...options, cwd: repo })
    if (program === 'go') {
      fs.writeFileSync(args[args.indexOf('-o') + 1], fs.readFileSync(path.join(options.cwd, 'compiler-input.txt')))
      return ''
    }
    if (program === 'pnpm') {
      assert.ok(!args.includes('@cdnca/control-site'), 'the community edition builds no public website')
      if (args.includes('build')) {
        webEnv.push(options.env)
        fs.mkdirSync(path.join(options.cwd, 'apps/web/dist'), { recursive: true })
        fs.writeFileSync(path.join(options.cwd, 'apps/web/dist/index.html'), 'candidate web\n')
      }
      return ''
    }
    return realExec(program, args, options)
  })
  syncBuiltinESMExports()
  t.after(() => { command.mock.restore(); syncBuiltinESMExports() })
  return { previousRelease, parent, commit, tree, previousCommit, webEnv }
}

test('chained build refreshes the served node installer from source and tags the Web build with the commit', (t) => {
  const { previousRelease, parent, commit, previousCommit, webEnv } = chainedBuildFixture(t)
  const outputDir = path.join(parent, 'built')
  const result = buildNativeRelease({ commit, remoteRef: 'refs/heads/main', previousRelease, outputDir,
    version: '2026.10.9', arch: 'amd64', allowEmptySiteKey: true, keyID: 'fixture-key' })
  assert.equal(result.source.previous_commit, previousCommit)
  assert.equal(fs.readFileSync(path.join(outputDir, 'payload/static/web/downloads/install-node.sh'), 'utf8'), '#!/usr/bin/env bash\necho candidate installer\n')
  assert.equal(fs.existsSync(path.join(outputDir, 'payload/static/web/site')), false)
  const manifest = JSON.parse(fs.readFileSync(path.join(outputDir, 'release.manifest.json'), 'utf8'))
  assert.deepEqual(manifest.files.find((file) => file.path === 'static/web/downloads/install-node.sh').mode, 0o644)
  // 卡 41：续链构建用本次源码刷新随包 root 恢复手册。
  assert.equal(fs.readFileSync(path.join(outputDir, 'payload/docs/platform-admin-recovery.md'), 'utf8'), '# recovery candidate\n')
  assert.equal(manifest.files.find((file) => file.path === 'docs/platform-admin-recovery.md').mode, 0o644)
  assert.equal(webEnv.length, 1)
  assert.equal(webEnv[0].VITE_RELEASE, commit)
  assert.equal(webEnv[0].VITE_API_BASE_URL, '')
  // A chained release carries no first-install markers and no separate runner (outer prepare builds it).
  const build = JSON.parse(fs.readFileSync(path.join(outputDir, 'build.json'), 'utf8'))
  assert.equal(build.installation_mode, undefined); assert.equal(build.runner, undefined)
  // Up scripts only, byte-for-byte from source, plus the helper that applies them.
  const clickhouse = manifest.files.filter((file) => file.path.startsWith('clickhouse/'))
  assert.deepEqual(clickhouse.map((file) => [file.path, file.mode]), [['clickhouse/configure-clickhouse.py', 0o644],
    ['clickhouse/migrations/001_fixture_1.up.sql', 0o644], ['clickhouse/migrations/002_fixture_2.up.sql', 0o644]])
  assert.equal(fs.readFileSync(path.join(outputDir, 'payload/clickhouse/migrations/002_fixture_2.up.sql'), 'utf8'),
    'CREATE TABLE IF NOT EXISTS t2 (x UInt8) ENGINE = Memory;\n')
})

test('ClickHouse migrations in a release chain may only be appended', () => {
  const file = (name, sha = 'a') => ({ path: `clickhouse/migrations/${name}.up.sql`, sha256: sha.repeat(64), bytes: 9, mode: 0o644 })
  const script = { path: 'clickhouse/configure-clickhouse.py', sha256: 'f'.repeat(64), bytes: 9, mode: 0o644 }
  const previous = { files: [script, file('001_one'), file('002_two')] }
  assert.deepEqual(assertAppendOnlyClickHouse(previous, { files: [{ ...script, sha256: 'e'.repeat(64) }, file('001_one'), file('002_two'), file('003_three')] }), ['003_three'])
  assert.deepEqual(assertAppendOnlyClickHouse({ files: [] }, previous), ['001_one', '002_two'])
  for (const [label, files, error] of [
    ['changed', [script, file('001_one', 'b'), file('002_two')], /applied ClickHouse migration changed/],
    ['removed', [script, file('001_one')], /applied ClickHouse migration changed or removed/],
    ['gap', [script, file('001_one'), file('002_two'), file('004_four')], /invalid ClickHouse migration/],
    ['helper removed', [file('001_one'), file('002_two')], /helper removed/],
  ]) assert.throws(() => assertAppendOnlyClickHouse(previous, { files }), error, label)
})

test('ClickHouse release inputs must be contiguous', (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-ch-release-')))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const source = path.join(root, 'source'), release = path.join(root, 'release')
  writeClickHouseSource(source, 3)
  fs.mkdirSync(path.join(release, 'clickhouse/migrations'), { recursive: true })
  fs.writeFileSync(path.join(release, 'clickhouse/migrations/009_stale.up.sql'), 'stale baseline copy\n')
  copyNativeClickHouse(source, release)
  assert.deepEqual(fs.readdirSync(path.join(release, 'clickhouse/migrations')).sort(), ['001_fixture_1.up.sql', '002_fixture_2.up.sql', '003_fixture_3.up.sql'])
  fs.unlinkSync(path.join(source, 'infra/clickhouse/migrations/002_fixture_2.up.sql'))
  assert.throws(() => copyNativeClickHouse(source, release), /contiguous/)
})

test('chained build refuses a source tree without the node installer', (t) => {
  const { previousRelease, parent } = chainedBuildFixture(t)
  const repo = path.join(parent, 'repo'), git = (args) => childProcess.execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim()
  git(['rm', '--quiet', 'scripts/install-node.sh'])
  git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'drop installer'])
  git(['push', '--quiet', 'origin', 'main'])
  assert.throws(() => buildNativeRelease({ commit: git(['rev-parse', 'HEAD']), remoteRef: 'refs/heads/main', previousRelease,
    outputDir: path.join(parent, 'built'), version: '2026.10.9', arch: 'amd64', allowEmptySiteKey: true, keyID: 'fixture-key' }), /node installer/)
  assert.equal(fs.existsSync(path.join(parent, 'built')), false)
})

test('upgrade compilation ignores local Git blob replacements and uses the pushed tree bytes', (t) => {
  const previousRelease = fs.realpathSync(fixture(t)), parent = fs.realpathSync(fixture(t))
  const repo = path.join(parent, 'repo'), remote = path.join(parent, 'remote.git'), realExec = childProcess.execFileSync
  fs.mkdirSync(repo)
  const git = (args, options = {}) => realExec('git', args, { cwd: repo, encoding: 'utf8', ...options }).trim()
  git(['init', '--quiet', '--template='])
  fs.writeFileSync(path.join(repo, 'compiler-input.txt'), 'original source\n')
  fs.mkdirSync(path.join(repo, 'scripts'))
  fs.writeFileSync(path.join(repo, 'scripts/install-node.sh'), '#!/usr/bin/env bash\n', { mode: 0o755 })
  fs.mkdirSync(path.join(repo, 'docs/runbooks'), { recursive: true })
  fs.writeFileSync(path.join(repo, 'docs/runbooks/platform-admin-recovery.md'), '# recovery\n')
  fs.mkdirSync(path.join(repo, 'services/control-api/migrations'), { recursive: true })
  fs.copyFileSync(path.join(previousRelease, 'migrations/001_test.up.sql'), path.join(repo, 'services/control-api/migrations/001_test.up.sql'))
  writeClickHouseSource(repo)
  git(['add', '--', 'compiler-input.txt', 'scripts', 'services', 'infra', 'docs'])
  const commitArgs = ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet']
  git([...commitArgs, '-m', 'previous'])
  const previousCommit = git(['rev-parse', 'HEAD']), previousTree = git(['rev-parse', 'HEAD^{tree}'])
  fs.writeFileSync(path.join(previousRelease, 'release.manifest.json'), JSON.stringify(createNativeManifest(previousRelease, {
    ...metadata, source: { ...metadata.source, commit: previousCommit, tree: previousTree },
  })))
  fs.writeFileSync(path.join(repo, 'compiler-input.txt'), 'pushed source\n')
  git(['add', '--', 'compiler-input.txt']); git([...commitArgs, '-m', 'candidate'])
  git(['branch', '-M', 'main'])
  const commit = git(['rev-parse', 'HEAD']), tree = git(['rev-parse', 'HEAD^{tree}'])
  git(['clone', '--quiet', '--bare', '--no-hardlinks', repo, remote]); git(['remote', 'add', 'origin', remote])
  const blob = git(['rev-parse', 'HEAD:compiler-input.txt'])
  const replacement = git(['hash-object', '-w', '--stdin'], { input: 'uncommitted replacement\n' })
  git(['replace', blob, replacement])
  assert.equal(git(['show', 'HEAD:compiler-input.txt']), 'uncommitted replacement')
  const command = t.mock.method(childProcess, 'execFileSync', (program, args, options) => {
    if (program === 'git') return realExec(program, args, { ...options, cwd: repo })
    if (program === 'go') {
      fs.writeFileSync(args[args.indexOf('-o') + 1], fs.readFileSync(path.join(options.cwd, 'compiler-input.txt')))
      return ''
    }
    if (program === 'pnpm') {
      assert.ok(!args.includes('@cdnca/control-site'), 'the community edition builds no public website')
      if (args.includes('build')) {
        fs.mkdirSync(path.join(options.cwd, 'apps/web/dist'), { recursive: true })
        fs.writeFileSync(path.join(options.cwd, 'apps/web/dist/index.html'), 'candidate web\n')
      }
      return ''
    }
    return realExec(program, args, options)
  })
  syncBuiltinESMExports()
  t.after(() => { command.mock.restore(); syncBuiltinESMExports() })
  const outputDir = path.join(parent, 'built')
  const result = buildNativeRelease({ commit, remoteRef: 'refs/heads/main', previousRelease, outputDir,
    version: '2026.10.9', arch: 'amd64', allowEmptySiteKey: true, keyID: 'fixture-key' })
  assert.deepEqual(result.source, { commit, tree, previous_commit: previousCommit })
  assert.equal(fs.readFileSync(path.join(outputDir, 'payload/bin/control-api'), 'utf8'), 'pushed source\n')
})

test('schema gate facts come from the migration head; the rollback range is declared and must be older', () => {
  const manifest = { version: '1.0.36', files: [
    { path: 'migrations/298_payment_channels.up.sql' }, { path: 'migrations/302_release_gate.down.sql' },
    { path: 'migrations/302_release_gate.up.sql' }, { path: 'bin/control-api' }] }
  assert.deepEqual(nativeSchemaGateFacts(manifest), { control_schema_head: 302 })
  assert.deepEqual(nativeSchemaGateFacts(manifest, '1.0.35'), { control_schema_head: 302, rollback_min_version: '1.0.35' })
  for (const bad of ['1.0.36', '1.0.40', 'v1.0.35', '1.0']) assert.throws(() => nativeSchemaGateFacts(manifest, bad))
  assert.throws(() => nativeSchemaGateFacts({ version: '1.0.36', files: [{ path: 'bin/control-api' }] }))
})
