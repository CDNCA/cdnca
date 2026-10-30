import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import childProcess from 'node:child_process'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { createNativeManifest, assertAppendOnlyMigrations } from './native-release-package.mjs'
import { buildNativeSchemaUpgrade } from './native-management-schema-build.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const realExec = childProcess.execFileSync
const encode = (value) => JSON.stringify(value, null, 2) + '\n'
const hash = (value) => createHash('sha256').update(value).digest('hex')
const stems = { 270: '270_l2_topology_default_region', 271: '271_node_network_inventory',
  272: '272_site_group_administration', 273: '273_validator_search_path',
  274: '274_node_line_endpoint_sort_order', 275: '275_node_line_endpoint_display_ids',
  276: '276_certificate_asset_owner', 277: '277_node_session_capabilities' }
const baseline117 = 'd937236fba23ecf63319862c68e78b50158824e4'
const baseline122 = '2166adcd3719d10e69ce427c2ca6af59d572792f'
const initialPredecessor = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'
const git = (cwd, args, options = {}) => realExec('git', args, { cwd, encoding: 'utf8', ...options }).trim()

function schemaBuildArchive(directory, payload, manifest, signed) {
  const filename = signed ? 'native-management.tar' : 'native-management.unsigned.tar'
  const list = path.join(directory, 'members')
  fs.writeFileSync(list, ['release.manifest.json', ...(signed ? ['release.manifest.sig'] : []), ...manifest.files.map((file) => file.path)].join('\n') + '\n')
  const ownership = realExec('tar', ['--version'], { encoding: 'utf8' }).includes('bsdtar')
    ? ['--uid', '0', '--gid', '0', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
  realExec('tar', ['--format=ustar', ...ownership, '-cf', path.join(directory, filename), '-T', list], { cwd: payload })
  fs.unlinkSync(list)
  return filename
}

function refreshSchemaFixture(fixture, signed = false) {
  const { directory, payload, metadata } = signed ? fixture.baseline : fixture.initial
  const firstBaseline = !signed || fixture.head === 277
  const manifest = createNativeManifest(payload, metadata), raw = encode(manifest)
  fs.writeFileSync(path.join(payload, 'release.manifest.json'), raw, { mode: 0o644 })
  fs.writeFileSync(path.join(directory, 'release.manifest.json'), raw, { mode: 0o644 })
  if (signed) {
    const signature = sign(null, Buffer.from(manifest.schema + '\n' + raw), fixture.privateKey).toString('base64') + '\n'
    fs.writeFileSync(path.join(payload, 'release.manifest.sig'), signature, { mode: 0o644 })
    fs.writeFileSync(path.join(directory, 'release.manifest.sig'), signature, { mode: 0o644 })
  } else fs.writeFileSync(path.join(directory, 'release.signing-data'), manifest.schema + '\n' + raw, { mode: 0o600 })
  const file = schemaBuildArchive(directory, payload, manifest, signed), archive = fs.readFileSync(path.join(directory, file))
  const build = { schema: `cdnca.native-management.${signed ? 'signed' : 'unsigned'}-build/v2`,
    ...(firstBaseline ? { installation_mode: 'first-native-baseline', previous_source_semantics: 'release-lineage-not-host-deployment' } : {}),
    source: manifest.source, version: manifest.version, built_at: manifest.built_at, file,
    sha256: hash(archive), bytes: archive.length, signing_required: !signed }
  if (firstBaseline) {
    const runner = fs.readFileSync(path.join(directory, 'control-upgrade-runner'))
    build.runner = { file: 'control-upgrade-runner', sha256: hash(runner), bytes: runner.length,
      source: { commit: manifest.source.commit, tree: manifest.source.tree }, platform: manifest.platform,
      version: manifest.version, signing_required: true }
  }
  fs.writeFileSync(path.join(directory, 'build.json'), encode(build), { mode: 0o600 })
  return manifest
}

function schemaBuildFixture(t, head = 270) {
  const previousHead = [273, 275, 277].includes(head) ? head - 2 : head - 1
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-schema-build-test-')))
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const repo = path.join(directory, 'repo'), remote = path.join(directory, 'remote.git')
  fs.mkdirSync(repo)
  git(repo, ['init', '--quiet', '--template='])
  const commit = (message) => git(repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', message])
  const sql = path.join(repo, 'services/control-api/migrations')
  let ancestor
  if ([275, 277].includes(head)) {
    // Read real historical objects without copying or mutating the shared repository.
    fs.writeFileSync(path.join(repo, '.git/objects/info/alternates'), git(repository, ['rev-parse', '--git-path', 'objects']) + '\n')
    const baseline = head === 275 ? baseline117 : baseline122
    git(repo, ['update-ref', 'HEAD', baseline]); git(repo, ['read-tree', baseline])
    realExec('tar', ['-xf', '-', '-C', repo], { input: realExec('git', ['archive', baseline, 'services/control-api/migrations'], { cwd: repo, maxBuffer: 32 << 20 }) })
    ancestor = head === 275 ? '7cf95a9c2e76618804a6010cc24dd1e454982d5e' : initialPredecessor
  } else {
    fs.writeFileSync(path.join(repo, 'root.txt'), 'published predecessor\n')
    git(repo, ['add', '--', 'root.txt']); commit('lineage')
    ancestor = git(repo, ['rev-parse', 'HEAD'])
    fs.mkdirSync(sql, { recursive: true })
    for (let index = 1; index <= previousHead; index++) {
      for (const direction of ['up', 'down']) {
        fs.writeFileSync(path.join(sql, `${stems[index] ?? `${String(index).padStart(3, '0')}_fixture`}.${direction}.sql`), `-- ${index} ${direction}\n`, { mode: 0o644 })
      }
    }
    git(repo, ['add', '--', 'services']); commit('baseline')
  }
  const previous = git(repo, ['rev-parse', 'HEAD']), previousTree = git(repo, ['rev-parse', 'HEAD^{tree}'])
  for (let index = previousHead + 1; index <= head; index++) {
    for (const direction of ['up', 'down']) {
      const filename = `${stems[index]}.${direction}.sql`
      fs.writeFileSync(path.join(sql, filename), [275, 277].includes(head)
        ? fs.readFileSync(path.join(repository, 'services/control-api/migrations', filename)) : `-- ${index} ${direction}\n`)
    }
  }
  git(repo, ['add', '--', 'services/control-api/migrations']); commit('candidate')
  git(repo, ['branch', '-M', 'main'])
  const source = { commit: git(repo, ['rev-parse', 'HEAD']), tree: git(repo, ['rev-parse', 'HEAD^{tree}']), previous_commit: ancestor }
  git(directory, ['clone', '--quiet', '--bare', '--no-hardlinks', repo, remote]); git(repo, ['remote', 'add', 'origin', remote])
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const publicKeyPath = path.join(directory, 'public.pem')
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))
  const baseline = { directory: path.join(directory, 'baseline'), payload: path.join(directory, 'baseline-payload'),
    metadata: { key_id: 'fixture-key', version: head === 277 ? '1.0.22' : head === 275 ? '1.0.17' : head === 273 ? '1.0.15' : head === 270 ? '1.0.11' : '1.0.12', built_at: '2026-10-08T00:00:00Z',
      source: { commit: previous, tree: previousTree, previous_commit: ancestor }, platform: { os: 'linux', arch: 'amd64' } } }
  const initial = { directory: path.join(directory, 'initial'), payload: path.join(directory, 'initial/payload'),
    metadata: { ...baseline.metadata, version: head === 277 ? '1.0.23' : head === 275 ? '1.0.22' : head === 273 ? '1.0.16' : head === 270 ? '1.0.12' : '1.0.13', built_at: '2026-10-09T00:00:00Z', source } }
  const elf = Buffer.alloc(128)
  elf.write('\x7fELF', 0, 'binary'); elf[4] = 2; elf[5] = 1; elf[6] = 1; elf.writeUInt16LE(2, 16); elf.writeUInt16LE(62, 18)
  for (const item of [baseline, initial]) {
    fs.mkdirSync(item.directory)
    for (const folder of ['bin', 'static/web/assets', 'migrations']) fs.mkdirSync(path.join(item.payload, folder), { recursive: true })
    for (const binary of ['control-api', 'agent-gateway']) fs.writeFileSync(path.join(item.payload, 'bin', binary), elf, { mode: 0o755 })
    fs.writeFileSync(path.join(item.payload, 'static/web/index.html'), '<script src="/runtime-config.js"></script>' + item.metadata.version)
    fs.writeFileSync(path.join(item.payload, 'static/web/runtime-config.js'), `runtime-${item.metadata.version}`)
    fs.writeFileSync(path.join(item.payload, `static/web/assets/${item.metadata.version}.js`), item.metadata.version)
    for (const name of fs.readdirSync(sql)) {
      if (!/^\d{3}_[a-z0-9_]+\.(up|down)\.sql$/.test(name)) continue
      if (item === baseline && Number(name.slice(0, 3)) > previousHead) continue
      fs.copyFileSync(path.join(sql, name), path.join(item.payload, 'migrations', name))
    }
  }
  fs.mkdirSync(path.join(baseline.payload, 'preserved'))
  fs.writeFileSync(path.join(baseline.payload, 'preserved/operational-file'), 'keep complete parent\n', { mode: 0o755 })
  fs.writeFileSync(path.join(baseline.payload, 'static/web/logo-old.png'), 'keep old public path\n')
  fs.writeFileSync(path.join(initial.directory, 'control-upgrade-runner'), elf, { mode: 0o755 })
  if (head === 277) fs.writeFileSync(path.join(baseline.directory, 'control-upgrade-runner'), elf, { mode: 0o755 })
  const fixture = { directory, repo, remote, privateKey, publicKeyPath, baseline, initial, head,
    options: { commit: source.commit, remoteRef: 'refs/heads/main', initialBuildDir: initial.directory,
      baselineBuildDir: baseline.directory, artifactPublicKeyPath: publicKeyPath, outputDir: path.join(directory, 'output') } }
  refreshSchemaFixture(fixture, true); refreshSchemaFixture(fixture)
  return fixture
}

function schemaBuildCommands(t, fixture, before) {
  const calls = []
  const mock = t.mock.method(childProcess, 'execFileSync', (command, args, options) => {
    calls.push({ command, args })
    if (command === 'git') {
      assert.equal(args[0], '--no-replace-objects')
      assert.equal(options.cwd, repository)
      options = { ...options, cwd: fixture.repo }
    }
    before?.(command, args, options)
    return realExec(command, args, options)
  })
  syncBuiltinESMExports()
  t.after(() => { mock.mock.restore(); syncBuiltinESMExports() })
  return calls
}

for (const head of [270, 271, 273, 275, 277]) test(`clones the signed ${[273, 275, 277].includes(head) ? head - 2 : head - 1} baseline and adds only the exact schema ${head} pairs`, (t) => {
  const fixture = schemaBuildFixture(t, head), calls = schemaBuildCommands(t, fixture)
  const baseline = fs.readFileSync(path.join(fixture.baseline.directory, 'release.manifest.json'))
  const initial = fs.readFileSync(path.join(fixture.initial.directory, 'release.manifest.json'))
  const result = buildNativeSchemaUpgrade(fixture.options), output = fixture.options.outputDir
  assert.equal(result.schema, 'cdnca.native-management.unsigned-build/v2')
  assert.equal(result.signing_required, true)
  assert.equal(result.source.previous_commit, fixture.baseline.metadata.source.commit)
  if (head === 275) assert.equal(result.source.previous_commit, baseline117)
  if (head === 277) assert.equal(result.source.previous_commit, baseline122)
  assert.equal(result.source.commit, fixture.options.commit)
  assert.equal(result.built_at, fixture.initial.metadata.built_at)
  assert.equal(result.version, fixture.initial.metadata.version)
  assert.equal(result.installation_mode, undefined); assert.equal(result.runner, undefined)
  assert.deepEqual(fs.readdirSync(output).sort(), ['build.json', 'native-management.unsigned.tar', 'payload', 'release.manifest.json', 'release.signing-data'])
  const manifest = JSON.parse(fs.readFileSync(path.join(output, 'release.manifest.json')))
  assert.deepEqual(createNativeManifest(path.join(output, 'payload'), manifest), manifest)
  for (const file of JSON.parse(baseline).files) {
    const current = manifest.files.find((item) => item.path === file.path)
    assert.ok(current, `preserved parent path ${file.path}`)
    if (!['bin/control-api', 'bin/agent-gateway', 'static/web/index.html'].includes(file.path)) assert.deepEqual(current, file)
  }
  assert.equal(fs.readFileSync(path.join(output, 'payload/static/web/runtime-config.js'), 'utf8'), `runtime-${fixture.baseline.metadata.version}`)
  assert.equal(fs.readFileSync(path.join(output, 'payload/preserved/operational-file'), 'utf8'), 'keep complete parent\n')
  assert.equal(fs.statSync(path.join(output, 'payload/preserved/operational-file')).mode & 0o777, 0o755)
  assert.ok(fs.existsSync(path.join(output, `payload/static/web/assets/${fixture.baseline.metadata.version}.js`)))
  assert.ok(fs.existsSync(path.join(output, 'payload/static/web/logo-old.png')))
  assert.equal(manifest.files.filter((file) => file.path.startsWith('migrations/')).length, head * 2)
  const previousHead = [273, 275, 277].includes(head) ? head - 2 : head - 1
  assert.deepEqual(assertAppendOnlyMigrations(JSON.parse(baseline), manifest),
    Array.from({ length: head - previousHead }, (_, index) => stems[previousHead + 1 + index]))
  assert.equal(result.sha256, hash(fs.readFileSync(path.join(output, result.file))))
  assert.equal(fs.readFileSync(path.join(output, 'release.signing-data'), 'utf8'), manifest.schema + '\n' + encode(manifest))
  assert.deepEqual(fs.readFileSync(path.join(fixture.baseline.directory, 'release.manifest.json')), baseline)
  assert.deepEqual(fs.readFileSync(path.join(fixture.initial.directory, 'release.manifest.json')), initial)
  assert.equal(calls.filter((call) => call.command === 'git' && call.args.includes('ls-remote')).length, 2)
  assert.ok(calls.every((call) => ['git', 'tar'].includes(call.command)))
})

for (const failure of ['missing intermediate up', 'missing final down', 'wrong previous version', 'unsupported later version']) {
  test(`116 schema transition rejects ${failure}`, (t) => {
    const fixture = schemaBuildFixture(t, 273)
    if (failure === 'missing intermediate up') fs.unlinkSync(path.join(fixture.initial.payload, 'migrations/272_site_group_administration.up.sql'))
    if (failure === 'missing final down') fs.unlinkSync(path.join(fixture.initial.payload, 'migrations/273_validator_search_path.down.sql'))
    if (failure === 'wrong previous version') { fixture.baseline.metadata.version = '1.0.14'; refreshSchemaFixture(fixture, true) }
    if (failure === 'unsupported later version') fixture.initial.metadata.version = '1.0.17'
    refreshSchemaFixture(fixture); schemaBuildCommands(t, fixture)
    assert.throws(() => buildNativeSchemaUpgrade(fixture.options), /migration|SQL|transition/)
    assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'build.json')), false)
  })
}

for (const failure of ['missing 274 up', 'missing 275 down', 'missing old SQL', 'changed old SQL', 'changed old SQL mode',
  'wrong previous version', 'wrong baseline source', 'unsupported 121', 'unsupported 123', 'non-descendant candidate',
  'unexpected 276 SQL', 'new SQL differs from source', 'immutable asset collision']) {
  test(`122 schema transition rejects ${failure}`, (t) => {
    const fixture = schemaBuildFixture(t, 275), { initial, baseline, options } = fixture
    const original = fs.readFileSync(path.join(baseline.directory, 'native-management.tar'))
    const oldName = '273_validator_search_path.up.sql', old = path.join(initial.payload, 'migrations', oldName)
    if (failure === 'missing 274 up') fs.unlinkSync(path.join(initial.payload, 'migrations/274_node_line_endpoint_sort_order.up.sql'))
    if (failure === 'missing 275 down') fs.unlinkSync(path.join(initial.payload, 'migrations/275_node_line_endpoint_display_ids.down.sql'))
    if (failure === 'missing old SQL') fs.unlinkSync(old)
    if (failure === 'changed old SQL') {
      fs.appendFileSync(old, '-- replaced historical SQL\n')
      fs.copyFileSync(old, path.join(fixture.repo, 'services/control-api/migrations', oldName))
    }
    if (failure === 'changed old SQL mode') fs.chmodSync(old, 0o755)
    if (failure === 'wrong previous version') baseline.metadata.version = '1.0.16'
    if (failure === 'wrong baseline source') baseline.metadata.source.commit = git(fixture.repo,
      ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', baseline.metadata.source.tree,
        '-p', baseline.metadata.source.previous_commit, '-m', 'different signed 117 source'])
    if (['wrong previous version', 'wrong baseline source'].includes(failure)) refreshSchemaFixture(fixture, true)
    if (failure === 'unsupported 121') initial.metadata.version = '1.0.21'
    if (failure === 'unsupported 123') initial.metadata.version = '1.0.23'
    if (failure === 'unexpected 276 SQL') {
      for (const direction of ['up', 'down']) {
        const filename = `276_unapproved.${direction}.sql`
        fs.writeFileSync(path.join(initial.payload, 'migrations', filename), '-- not this transition\n')
        fs.copyFileSync(path.join(initial.payload, 'migrations', filename), path.join(fixture.repo, 'services/control-api/migrations', filename))
      }
    }
    if (['changed old SQL', 'unexpected 276 SQL'].includes(failure)) {
      git(fixture.repo, ['add', '--', 'services/control-api/migrations'])
      git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', failure])
      initial.metadata.source.commit = git(fixture.repo, ['rev-parse', 'HEAD'])
      initial.metadata.source.tree = git(fixture.repo, ['rev-parse', 'HEAD^{tree}'])
      options.commit = initial.metadata.source.commit
      git(fixture.repo, ['push', '--quiet', 'origin', 'main'])
    }
    if (failure === 'non-descendant candidate') {
      initial.metadata.source.commit = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        'commit-tree', initial.metadata.source.tree, '-p', baseline.metadata.source.previous_commit, '-m', 'unrelated candidate'])
      options.commit = initial.metadata.source.commit
      git(fixture.remote, ['fetch', '--quiet', fixture.repo, options.commit])
      git(fixture.remote, ['update-ref', 'refs/heads/main', options.commit])
    }
    if (failure === 'new SQL differs from source') fs.appendFileSync(path.join(initial.payload, 'migrations/275_node_line_endpoint_display_ids.up.sql'), '-- uncommitted\n')
    if (failure === 'immutable asset collision') fs.writeFileSync(path.join(initial.payload, 'static/web/assets/1.0.17.js'), 'different old asset')
    refreshSchemaFixture(fixture); schemaBuildCommands(t, fixture)
    const error = failure === 'non-descendant candidate' ? /command failed/
      : failure === 'immutable asset collision' ? /collision/
        : /migration|SQL|transition|source identity/
    assert.throws(() => buildNativeSchemaUpgrade(options), error)
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
    if (!['wrong previous version', 'wrong baseline source'].includes(failure)) {
      assert.deepEqual(fs.readFileSync(path.join(baseline.directory, 'native-management.tar')), original)
    }
  })
}

test('123 preserves the original signed first-baseline sidecar and runner without distributing either', function schema123PreservesFirstBaseline(t) {
  const fixture = schemaBuildFixture(t, 277), { baseline, options } = fixture
  const names = fs.readdirSync(baseline.directory).sort()
  const original = Object.fromEntries(names.map((name) => [name, fs.readFileSync(path.join(baseline.directory, name))]))
  const build = JSON.parse(original['build.json'])
  assert.equal(build.installation_mode, 'first-native-baseline')
  assert.equal(build.previous_source_semantics, 'release-lineage-not-host-deployment')
  assert.equal(build.source.previous_commit, initialPredecessor)
  assert.equal(build.runner.source.commit, baseline122)
  schemaBuildCommands(t, fixture)
  const result = buildNativeSchemaUpgrade(options)
  assert.equal(result.source.previous_commit, baseline122)
  assert.equal(result.runner, undefined)
  assert.equal(result.installation_mode, undefined)
  assert.equal(fs.existsSync(path.join(options.outputDir, 'control-upgrade-runner')), false)
  const manifest = JSON.parse(fs.readFileSync(path.join(options.outputDir, 'release.manifest.json')))
  assert.ok(manifest.files.every((file) => !file.path.split('/').some((part) => ['.git', 'source.bundle', 'control-upgrade-runner'].includes(part))))
  assert.deepEqual(fs.readdirSync(baseline.directory).sort(), names)
  for (const name of names) assert.deepEqual(fs.readFileSync(path.join(baseline.directory, name)), original[name])
})

for (const failure of ['missing 276 up', 'missing 277 down', 'missing old SQL', 'changed old SQL', 'changed old SQL mode',
  'wrong baseline version', 'wrong baseline source', 'wrong baseline lineage', 'same target version', 'non-descendant candidate',
  'unapproved 278 SQL', 'changed reviewed 277 SQL', 'immutable asset collision', 'bad baseline signature', 'private source',
  'stripped first-baseline markers', 'missing baseline runner', 'changed baseline runner', 'baseline runner mode', 'baseline runner source',
  'baseline runner version', 'baseline runner platform', 'baseline runner ELF', 'baseline runner symlink', 'baseline runner changes during build']) {
  test(`123 schema transition rejects ${failure}`, function schema123Failure(t) {
    const fixture = schemaBuildFixture(t, 277), { baseline, initial, options } = fixture
    const oldName = '275_node_line_endpoint_display_ids.up.sql', old = path.join(initial.payload, 'migrations', oldName)
    const runner = path.join(baseline.directory, 'control-upgrade-runner')
    if (failure === 'missing 276 up') fs.unlinkSync(path.join(initial.payload, 'migrations/276_certificate_asset_owner.up.sql'))
    if (failure === 'missing 277 down') fs.unlinkSync(path.join(initial.payload, 'migrations/277_node_session_capabilities.down.sql'))
    if (failure === 'missing old SQL') fs.unlinkSync(old)
    if (failure === 'changed old SQL') {
      fs.appendFileSync(old, '-- changed historical SQL\n')
      fs.copyFileSync(old, path.join(fixture.repo, 'services/control-api/migrations', oldName))
    }
    if (failure === 'changed old SQL mode') fs.chmodSync(old, 0o755)
    if (failure === 'wrong baseline version') baseline.metadata.version = '1.0.21'
    if (failure === 'wrong baseline source') baseline.metadata.source.commit = git(fixture.repo,
      ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', baseline.metadata.source.tree,
        '-p', baseline.metadata.source.previous_commit, '-m', 'different first-baseline source'])
    if (failure === 'wrong baseline lineage') baseline.metadata.source.previous_commit = baseline117
    if (failure === 'same target version') initial.metadata.version = '1.0.22'
    if (failure === 'unapproved 278 SQL') {
      for (const direction of ['up', 'down']) {
        const filename = `278_unapproved.${direction}.sql`
        fs.writeFileSync(path.join(initial.payload, 'migrations', filename), '-- not approved\n')
        fs.copyFileSync(path.join(initial.payload, 'migrations', filename), path.join(fixture.repo, 'services/control-api/migrations', filename))
      }
    }
    if (failure === 'changed reviewed 277 SQL') {
      const filename = '277_node_session_capabilities.up.sql'
      fs.appendFileSync(path.join(initial.payload, 'migrations', filename), '-- different but committed SQL\n')
      fs.copyFileSync(path.join(initial.payload, 'migrations', filename), path.join(fixture.repo, 'services/control-api/migrations', filename))
    }
    if (['changed old SQL', 'unapproved 278 SQL', 'changed reviewed 277 SQL'].includes(failure)) {
      git(fixture.repo, ['add', '--', 'services/control-api/migrations'])
      git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', failure])
      initial.metadata.source.commit = git(fixture.repo, ['rev-parse', 'HEAD'])
      initial.metadata.source.tree = git(fixture.repo, ['rev-parse', 'HEAD^{tree}'])
      options.commit = initial.metadata.source.commit
      git(fixture.repo, ['push', '--quiet', 'origin', 'main'])
    }
    if (failure === 'non-descendant candidate') {
      initial.metadata.source.commit = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        'commit-tree', initial.metadata.source.tree, '-p', initialPredecessor, '-m', 'candidate outside B lineage'])
      options.commit = initial.metadata.source.commit
      git(fixture.remote, ['fetch', '--quiet', fixture.repo, options.commit]); git(fixture.remote, ['update-ref', 'refs/heads/main', options.commit])
    }
    if (failure === 'immutable asset collision') fs.writeFileSync(path.join(initial.payload, 'static/web/assets/1.0.22.js'), 'changed hashed asset')
    if (failure === 'private source') fs.writeFileSync(path.join(baseline.payload, 'source.bundle'), 'private Git source')
    if (failure === 'baseline runner ELF') fs.writeFileSync(runner, 'not an ELF executable')
    refreshSchemaFixture(fixture, true); refreshSchemaFixture(fixture)
    if (failure === 'bad baseline signature') fs.writeFileSync(path.join(baseline.directory, 'release.manifest.sig'), Buffer.alloc(64).toString('base64') + '\n')
    if (failure === 'missing baseline runner') fs.unlinkSync(runner)
    if (failure === 'changed baseline runner') fs.appendFileSync(runner, 'changed')
    if (failure === 'baseline runner mode') fs.chmodSync(runner, 0o644)
    if (failure === 'baseline runner symlink') { fs.renameSync(runner, runner + '.saved'); fs.symlinkSync(runner + '.saved', runner) }
    if (['stripped first-baseline markers', 'baseline runner source', 'baseline runner version', 'baseline runner platform'].includes(failure)) {
      const filename = path.join(baseline.directory, 'build.json'), build = JSON.parse(fs.readFileSync(filename))
      if (failure === 'stripped first-baseline markers') { delete build.installation_mode; delete build.previous_source_semantics; delete build.runner }
      if (failure === 'baseline runner source') build.runner.source.commit = baseline117
      if (failure === 'baseline runner version') build.runner.version = '1.0.21'
      if (failure === 'baseline runner platform') build.runner.platform.arch = 'arm64'
      fs.writeFileSync(filename, encode(build))
    }
    const original = fs.readFileSync(path.join(baseline.directory, 'native-management.tar'))
    schemaBuildCommands(t, fixture, (command, args) => {
      if (failure === 'baseline runner changes during build' && command === 'tar' && args.includes('-cf')) fs.appendFileSync(runner, 'concurrent change')
    })
    assert.throws(() => buildNativeSchemaUpgrade(options), /transition|source|provenance|inventory|runner|migration|SQL|collision|signature|ELF|command failed|link|canonical|input changed/)
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
    assert.deepEqual(fs.readFileSync(path.join(baseline.directory, 'native-management.tar')), original)
  })
}

test('rejects missing arguments without executing commands', (t) => {
  const command = t.mock.method(childProcess, 'execFileSync', () => { throw new Error('unexpected command') })
  syncBuiltinESMExports(); t.after(() => { command.mock.restore(); syncBuiltinESMExports() })
  assert.throws(() => buildNativeSchemaUpgrade({}), /arguments/)
  assert.equal(command.mock.callCount(), 0)
})

test('restrictive umask cannot change the canonical manifest or preserved runtime-config mode', (t) => {
  const fixture = schemaBuildFixture(t)
  fs.chmodSync(path.join(fixture.baseline.payload, 'static/web/runtime-config.js'), 0o755)
  refreshSchemaFixture(fixture, true); schemaBuildCommands(t, fixture)
  const mask = process.umask(0o077)
  try {
    buildNativeSchemaUpgrade(fixture.options)
    const output = fixture.options.outputDir
    assert.equal(fs.statSync(path.join(output, 'payload/release.manifest.json')).mode & 0o777, 0o644)
    assert.equal(fs.statSync(path.join(output, 'release.manifest.json')).mode & 0o777, 0o644)
    assert.equal(fs.statSync(path.join(output, 'payload/static/web/runtime-config.js')).mode & 0o777, 0o755)
  } finally { process.umask(mask) }
})

for (const failure of ['wrong public key', 'bad signature', 'initial used as baseline', 'initial lineage with stripped sidecar markers', 'wrong source', 'wrong tree',
  'wrong version', 'wrong key ID', 'platform mismatch', 'wrong previous commit', 'forged runner', 'bad signing data',
  'duplicate manifest key', 'additional build field', 'declared digest', 'declared bytes', 'baseline declared digest', 'shallow source',
  'private source', 'extra initial member', 'missing payload file', 'payload bytes', 'payload mode']) {
  test(`rejects ${failure} without a successful output record`, (t) => {
    const fixture = schemaBuildFixture(t), { baseline, initial, options } = fixture
    schemaBuildCommands(t, fixture)
    if (failure === 'wrong public key') fs.writeFileSync(options.artifactPublicKeyPath, generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }))
    if (failure === 'bad signature') fs.writeFileSync(path.join(baseline.directory, 'release.manifest.sig'), Buffer.alloc(64).toString('base64') + '\n')
    if (failure === 'initial used as baseline') options.baselineBuildDir = initial.directory
    if (failure === 'initial lineage with stripped sidecar markers') {
      baseline.metadata.source.previous_commit = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'; refreshSchemaFixture(fixture, true)
    }
    if (failure === 'wrong source') initial.metadata.source.commit = 'a'.repeat(40)
    if (failure === 'wrong tree') initial.metadata.source.tree = 'a'.repeat(40)
    if (failure === 'wrong version') initial.metadata.version = '1.0.14'
    if (failure === 'wrong key ID') initial.metadata.key_id = 'other-key'
    if (failure === 'platform mismatch') initial.metadata.platform = { os: 'linux', arch: 'arm64' }
    if (failure === 'wrong previous commit') initial.metadata.source.previous_commit = initial.metadata.source.commit
    if (['wrong source', 'wrong tree', 'wrong version', 'wrong key ID', 'platform mismatch', 'wrong previous commit'].includes(failure)) refreshSchemaFixture(fixture)
    if (failure === 'forged runner') fs.appendFileSync(path.join(initial.directory, 'control-upgrade-runner'), 'changed')
    if (failure === 'bad signing data') fs.appendFileSync(path.join(initial.directory, 'release.signing-data'), 'changed')
    if (failure === 'duplicate manifest key') {
      const filename = path.join(initial.directory, 'release.manifest.json')
      fs.writeFileSync(filename, fs.readFileSync(filename, 'utf8').replace('"version":', '"version": "1.0.1",\n  "version":'))
    }
    if (failure === 'additional build field') {
      const filename = path.join(initial.directory, 'build.json'), value = JSON.parse(fs.readFileSync(filename))
      fs.writeFileSync(filename, encode({ ...value, unexplained: true }))
    }
    if (['declared digest', 'declared bytes', 'baseline declared digest'].includes(failure)) {
      const filename = path.join(failure.startsWith('baseline') ? baseline.directory : initial.directory, 'build.json'), value = JSON.parse(fs.readFileSync(filename))
      if (failure === 'declared bytes') value.bytes++
      else value.sha256 = 'a'.repeat(64)
      fs.writeFileSync(filename, encode(value))
    }
    if (failure === 'shallow source') fs.writeFileSync(path.join(fixture.repo, '.git/shallow'), options.commit + '\n')
    if (failure === 'private source') {
      fs.writeFileSync(path.join(baseline.payload, 'source.bundle'), 'private history')
      refreshSchemaFixture(fixture, true)
    }
    if (failure === 'extra initial member') fs.writeFileSync(path.join(initial.directory, 'unexpected'), 'extra')
    if (failure === 'missing payload file') fs.unlinkSync(path.join(initial.payload, 'static/web/index.html'))
    if (failure === 'payload bytes') fs.appendFileSync(path.join(initial.payload, 'static/web/index.html'), 'changed')
    if (failure === 'payload mode') fs.chmodSync(path.join(initial.payload, 'static/web/index.html'), 0o755)
    assert.throws(() => buildNativeSchemaUpgrade(options))
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
  })
}

for (const failure of ['old SQL changed in candidate', 'old SQL mode', 'missing SQL', 'extra SQL', 'different new SQL name', 'source SQL mismatch', 'baseline head mismatch']) {
  test(`rejects ${failure} even when candidate metadata and tar hashes are consistent`, (t) => {
    const fixture = schemaBuildFixture(t), { initial, baseline, options } = fixture
    const old = path.join(initial.payload, 'migrations/001_fixture.up.sql')
    if (failure === 'old SQL changed in candidate') {
      fs.appendFileSync(old, '-- replaced old SQL\n')
      fs.copyFileSync(old, path.join(fixture.repo, 'services/control-api/migrations/001_fixture.up.sql'))
      git(fixture.repo, ['add', '--', 'services/control-api/migrations/001_fixture.up.sql'])
      git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'invalid old SQL'])
      initial.metadata.source.commit = git(fixture.repo, ['rev-parse', 'HEAD']); initial.metadata.source.tree = git(fixture.repo, ['rev-parse', 'HEAD^{tree}'])
      options.commit = initial.metadata.source.commit
      git(fixture.repo, ['push', '--quiet', 'origin', 'main'])
    }
    if (failure === 'old SQL mode') fs.chmodSync(old, 0o755)
    if (failure === 'missing SQL') fs.unlinkSync(path.join(initial.payload, 'migrations/270_l2_topology_default_region.down.sql'))
    if (failure === 'extra SQL') fs.writeFileSync(path.join(initial.payload, 'migrations/271_unapproved.up.sql'), '-- extra\n')
    if (failure === 'different new SQL name') fs.renameSync(path.join(initial.payload, 'migrations/270_l2_topology_default_region.up.sql'), path.join(initial.payload, 'migrations/270_unapproved.up.sql'))
    if (failure === 'source SQL mismatch') fs.appendFileSync(old, '-- differs from Git blob\n')
    if (failure === 'baseline head mismatch') { fs.unlinkSync(path.join(baseline.payload, 'migrations/269_fixture.down.sql')); refreshSchemaFixture(fixture, true) }
    refreshSchemaFixture(fixture)
    schemaBuildCommands(t, fixture)
    assert.throws(() => buildNativeSchemaUpgrade(options), /migration|SQL/)
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
  })
}

for (const failure of ['initial root symlink', 'baseline root symlink', 'input ancestor alias', 'output ancestor alias',
  'output inside baseline', 'output inside initial', 'existing output', 'dangling output', 'payload symlink', 'payload hard link',
  'manifest hard link', 'tar symlink', 'signature hard link', 'trust symlink', 'runner symlink']) {
  test(`rejects ${failure} without overwriting immutable inputs`, (t) => {
    const fixture = schemaBuildFixture(t), { directory, initial, baseline, options } = fixture
    const original = fs.readFileSync(path.join(baseline.directory, 'native-management.tar'))
    if (failure === 'initial root symlink') { fs.symlinkSync(initial.directory, path.join(directory, 'alias')); options.initialBuildDir = path.join(directory, 'alias') }
    if (failure === 'baseline root symlink') { fs.symlinkSync(baseline.directory, path.join(directory, 'alias')); options.baselineBuildDir = path.join(directory, 'alias') }
    if (failure === 'input ancestor alias') { fs.symlinkSync(directory, path.join(directory, 'alias')); options.initialBuildDir = path.join(directory, 'alias/initial') }
    if (failure === 'output ancestor alias') { fs.symlinkSync(baseline.directory, path.join(directory, 'alias')); options.outputDir = path.join(directory, 'alias/output') }
    if (failure === 'output inside baseline') options.outputDir = path.join(baseline.directory, 'output')
    if (failure === 'output inside initial') options.outputDir = path.join(initial.directory, 'output')
    if (failure === 'existing output') { fs.mkdirSync(options.outputDir); fs.writeFileSync(path.join(options.outputDir, 'keep'), 'existing') }
    if (failure === 'dangling output') fs.symlinkSync(path.join(directory, 'missing'), options.outputDir)
    const files = {
      'payload symlink': path.join(initial.payload, 'static/web/index.html'), 'payload hard link': path.join(initial.payload, 'static/web/index.html'),
      'manifest hard link': path.join(initial.directory, 'release.manifest.json'), 'tar symlink': path.join(initial.directory, 'native-management.unsigned.tar'),
      'signature hard link': path.join(baseline.directory, 'release.manifest.sig'), 'trust symlink': options.artifactPublicKeyPath,
      'runner symlink': path.join(initial.directory, 'control-upgrade-runner'),
    }
    if (files[failure]) {
      const filename = files[failure], saved = path.join(directory, 'saved')
      fs.renameSync(filename, saved)
      if (failure.includes('hard link')) fs.linkSync(saved, filename)
      else fs.symlinkSync(saved, filename)
    }
    schemaBuildCommands(t, fixture)
    assert.throws(() => buildNativeSchemaUpgrade(options), /canonical|link|output|inventory/)
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
    assert.deepEqual(fs.readFileSync(path.join(baseline.directory, 'native-management.tar')), original)
    if (failure === 'existing output') assert.equal(fs.readFileSync(path.join(options.outputDir, 'keep'), 'utf8'), 'existing')
  })
}

function corruptSchemaTar(fixture, kind) {
  const filename = path.join(fixture.initial.directory, 'native-management.unsigned.tar')
  let archive = fs.readFileSync(filename), offset = 0
  const ranges = []
  while (archive.subarray(offset, offset + 512).some((byte) => byte !== 0)) {
    const bytes = Number.parseInt(archive.subarray(offset + 124, offset + 136).toString(), 8)
    const next = offset + 512 + Math.ceil(bytes / 512) * 512
    ranges.push([offset, next]); offset = next
  }
  if (kind === 'duplicate member') archive = Buffer.concat([archive.subarray(...ranges[0]), archive])
  else if (kind === 'missing member') archive = archive.subarray(ranges[0][1])
  else if (kind === 'trailing bytes') archive = Buffer.concat([archive, Buffer.from('not archive padding')])
  else if (kind === 'tar checksum') archive[100] ^= 1
  else if (kind === 'tar bytes') archive[ranges[1][0] + 512] ^= 1
  else if (kind === 'missing EOF') archive = archive.subarray(0, offset)
  else {
    const header = archive.subarray(ranges[1][0], ranges[1][0] + 512)
    if (kind === 'symlink header') header.write('2', 156)
    if (kind === 'hard link header') header.write('1', 156)
    if (kind === 'PAX header') header.write('x', 156)
    if (kind === 'escaping member') { header.fill(0, 0, 100); header.write('../escape', 0) }
    if (kind === 'extra member') { header.fill(0, 0, 100); header.write('unlisted', 0) }
    if (kind === 'tar mode') header.write('0000777\0', 100, 'binary')
    if (kind === 'nonzero owner') header.write('0000001\0', 108, 'binary')
    if (kind === 'invalid mtime') header.write('not-a-time!\0', 136, 'binary')
    header.fill(32, 148, 156)
    const checksum = [...header].reduce((sum, byte) => sum + byte, 0)
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 'binary')
  }
  fs.writeFileSync(filename, archive)
  if (kind !== 'declared tar digest') {
    const buildFile = path.join(fixture.initial.directory, 'build.json'), build = JSON.parse(fs.readFileSync(buildFile))
    build.sha256 = hash(archive); build.bytes = archive.length; fs.writeFileSync(buildFile, encode(build))
  }
}

for (const failure of ['duplicate member', 'missing member', 'trailing bytes', 'tar checksum', 'tar bytes', 'missing EOF',
  'symlink header', 'hard link header', 'PAX header', 'escaping member', 'extra member', 'tar mode', 'nonzero owner', 'invalid mtime']) {
  test(`rejects ${failure} despite recomputed unsigned build hash`, (t) => {
    const fixture = schemaBuildFixture(t)
    corruptSchemaTar(fixture, failure); schemaBuildCommands(t, fixture)
    assert.throws(() => buildNativeSchemaUpgrade(fixture.options), /archive|USTAR/)
    assert.equal(fs.existsSync(path.join(fixture.options.outputDir, 'build.json')), false)
    assert.equal(fs.existsSync(path.join(fixture.directory, 'escape')), false)
  })
}

for (const failure of ['remote advanced before build', 'remote advances during build', 'unrelated baseline', 'Git SQL blob replacement', 'wrong ELF', 'immutable asset collision', 'immutable asset mode change', 'runtime hook lost']) {
  test(`validates ${failure} against immutable source and baseline facts`, (t) => {
    const fixture = schemaBuildFixture(t), { initial, baseline, options } = fixture
    let remoteChecks = 0
    schemaBuildCommands(t, fixture, (command, args) => {
      if (command === 'git' && args.includes('ls-remote')) {
        remoteChecks++
        if ((failure === 'remote advanced before build' && remoteChecks === 1) || (failure === 'remote advances during build' && remoteChecks === 2)) {
          git(fixture.remote, ['update-ref', 'refs/heads/main', baseline.metadata.source.commit])
        }
      }
    })
    if (failure === 'unrelated baseline') {
      const unrelated = git(fixture.repo, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit-tree', baseline.metadata.source.tree, '-p', baseline.metadata.source.previous_commit, '-m', 'other lineage'])
      baseline.metadata.source.commit = unrelated; refreshSchemaFixture(fixture, true)
    }
    if (failure === 'Git SQL blob replacement') {
      const blob = git(fixture.repo, ['rev-parse', `HEAD:services/control-api/migrations/${stems[fixture.head]}.up.sql`])
      const replacement = git(fixture.repo, ['hash-object', '-w', '--stdin'], { input: '-- replacement not in pushed commit\n' })
      git(fixture.repo, ['replace', blob, replacement])
      assert.equal(git(fixture.repo, ['show', `HEAD:services/control-api/migrations/${stems[fixture.head]}.up.sql`]), '-- replacement not in pushed commit')
    }
    if (failure === 'wrong ELF') { fs.writeFileSync(path.join(initial.payload, 'bin/control-api'), 'not ELF'); refreshSchemaFixture(fixture) }
    if (failure === 'immutable asset collision') {
      fs.writeFileSync(path.join(initial.payload, `static/web/assets/${baseline.metadata.version}.js`), 'wrong immutable asset')
      refreshSchemaFixture(fixture)
    }
    if (failure === 'immutable asset mode change') {
      fs.writeFileSync(path.join(initial.payload, `static/web/assets/${baseline.metadata.version}.js`), baseline.metadata.version, { mode: 0o755 })
      refreshSchemaFixture(fixture)
    }
    if (failure === 'runtime hook lost') { fs.writeFileSync(path.join(initial.payload, 'static/web/index.html'), 'new entry disconnected runtime'); refreshSchemaFixture(fixture) }
    if (failure === 'Git SQL blob replacement') {
      const result = buildNativeSchemaUpgrade(options)
      assert.equal(result.source.commit, options.commit)
      assert.equal(fs.readFileSync(path.join(options.outputDir, `payload/migrations/${stems[fixture.head]}.up.sql`), 'utf8'), `-- ${fixture.head} up\n`)
    } else {
      assert.throws(() => buildNativeSchemaUpgrade(options), /remote tip|command failed|ELF|collision|preserved baseline|runtime-config/)
      assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
    }
  })
}

for (const failure of ['clone becomes symlink', 'input changes during archive creation', 'archive changes while copying', 'payload manifest changes while copying', 'output signing-data write fails', 'output created concurrently']) {
  test(`leaves no successful build record when ${failure}`, (t) => {
    const fixture = schemaBuildFixture(t), { options, initial, baseline } = fixture
    schemaBuildCommands(t, fixture, (command, args) => {
      if (command === 'tar' && args.includes('-cf')) {
        if (failure === 'input changes during archive creation') fs.appendFileSync(path.join(initial.payload, 'static/web/index.html'), 'late mutation')
        if (failure === 'output created concurrently') { fs.mkdirSync(options.outputDir); fs.writeFileSync(path.join(options.outputDir, 'keep'), 'concurrent owner') }
      }
    })
    const originalCopy = fs.copyFileSync, originalTreeCopy = fs.cpSync, originalWrite = fs.writeFileSync
    const copy = t.mock.method(fs, 'copyFileSync', (source, target, flags) => {
      originalCopy(source, target, flags)
      if (failure === 'archive changes while copying' && target === path.join(options.outputDir, 'native-management.unsigned.tar')) fs.appendFileSync(target, 'late mutation')
    })
    const treeCopy = t.mock.method(fs, 'cpSync', (source, target, settings) => {
      if (failure === 'clone becomes symlink' && target.endsWith('/release')) return fs.symlinkSync(baseline.payload, target)
      originalTreeCopy(source, target, settings)
      if (failure === 'payload manifest changes while copying' && target === path.join(options.outputDir, 'payload')) originalWrite(path.join(target, 'release.manifest.json'), '{}')
    })
    const write = t.mock.method(fs, 'writeFileSync', (filename, data, settings) => {
      if (failure === 'output signing-data write fails' && filename === path.join(options.outputDir, 'release.signing-data')) throw new Error('simulated disk failure')
      return originalWrite(filename, data, settings)
    })
    syncBuiltinESMExports(); t.after(() => { copy.mock.restore(); treeCopy.mock.restore(); write.mock.restore(); syncBuiltinESMExports() })
    const before = fs.readFileSync(path.join(baseline.directory, 'release.manifest.json'))
    assert.throws(() => buildNativeSchemaUpgrade(options))
    assert.equal(fs.existsSync(path.join(options.outputDir, 'build.json')), false)
    assert.deepEqual(fs.readFileSync(path.join(baseline.directory, 'release.manifest.json')), before)
    if (failure === 'output created concurrently') assert.equal(fs.readFileSync(path.join(options.outputDir, 'keep'), 'utf8'), 'concurrent owner')
  })
}
