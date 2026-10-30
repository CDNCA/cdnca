#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const schema = 'cdnca.native-management.release/v1'
const signedSchema = 'cdnca.native-management.release/v2'
const objectID = /^[0-9a-f]{40}$/
// build.json previous_source_semantics of an initial baseline: the manifest names no predecessor.
export const initialBaselineSemantics = 'initial-baseline-no-predecessor'
const stableVersion = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const run = (cwd, command, args, env = process.env) => execFileSync(command, command === 'git' ? ['--no-replace-objects', ...args] : args, {
  cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 16 << 20,
}).trim()

export function createNativeManifest(directory, metadata) {
  if (metadata.key_id !== undefined && (typeof metadata.key_id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(metadata.key_id)) ||
      !stableVersion.test(metadata.version) || !['amd64', 'arm64'].includes(metadata.platform?.arch) ||
      metadata.platform?.os !== 'linux' || !objectID.test(metadata.source?.commit) ||
      !objectID.test(metadata.source?.tree) || (metadata.source.previous_commit !== undefined && !objectID.test(metadata.source.previous_commit)) ||
      !Number.isFinite(Date.parse(metadata.built_at)) ||
      new Date(metadata.built_at).toISOString().replace('.000Z', 'Z') !== metadata.built_at) {
    throw new Error('invalid native release metadata')
  }
  const files = []
  const walk = (relative = '') => {
    for (const name of fs.readdirSync(path.join(directory, relative)).sort()) {
      const member = relative ? `${relative}/${name}` : name
      const filename = path.join(directory, member)
      const stat = fs.lstatSync(filename)
      if (stat.isSymbolicLink() || stat.isFile() && stat.nlink !== 1) throw new Error(`release contains a link: ${member}`)
      if (stat.isDirectory()) { walk(member); continue }
      if (!stat.isFile() || /[\r\n\\]/.test(member) || member.startsWith('-')) throw new Error(`unsafe release member: ${member}`)
      if (member === 'release.manifest.json') continue
      const mode = stat.mode & 0o7777
      if (member === 'release.manifest.sig') {
        if (metadata.key_id === undefined || mode !== 0o644) throw new Error('unexpected native release signature')
        continue
      }
      if (mode !== 0o644 && mode !== 0o755) throw new Error(`invalid release mode: ${member}`)
      files.push({ path: member, sha256: sha256(fs.readFileSync(filename)), bytes: stat.size, mode })
    }
  }
  walk()
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
  for (const required of ['bin/control-api', 'bin/agent-gateway', 'static/web/index.html']) {
    const entry = files.find((file) => file.path === required)
    if (!entry || entry.bytes < 1 || entry.mode !== (required.startsWith('bin/') ? 0o755 : 0o644)) {
      throw new Error(`missing or invalid required release file: ${required}`)
    }
  }
  if (!files.some((file) => file.path.startsWith('migrations/') && file.path.endsWith('.sql'))) {
    throw new Error('release has no migration files')
  }
  return { schema: metadata.key_id === undefined ? schema : signedSchema,
    ...(metadata.key_id === undefined ? {} : { key_id: metadata.key_id }), version: metadata.version, built_at: metadata.built_at,
    // An initial baseline (native-initial-release-package.mjs --baseline) has no predecessor at all.
    source: { commit: metadata.source.commit, tree: metadata.source.tree,
      ...(metadata.source.previous_commit === undefined ? {} : { previous_commit: metadata.source.previous_commit }) },
    platform: { os: 'linux', arch: metadata.platform.arch }, files }
}

export function verifyNativeManifestSignature(raw, signature, publicKey) {
  const manifest = JSON.parse(raw)
  if (manifest.schema !== signedSchema || typeof manifest.key_id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(manifest.key_id) ||
      !/^[A-Za-z0-9+/]{86}==(?:\n)?$/.test(signature) || Buffer.byteLength(signature) > 128) throw new Error('invalid native signature encoding')
  const encoded = signature.replace(/\n$/, ''), key = createPublicKey(publicKey)
  if (key.asymmetricKeyType !== 'ed25519' || Buffer.from(encoded, 'base64').toString('base64') !== encoded ||
      !verify(null, Buffer.concat([Buffer.from(signedSchema + '\n'), Buffer.from(raw)]), key, Buffer.from(encoded, 'base64'))) {
    throw new Error('invalid native manifest signature')
  }
  return manifest
}

const migrationFile = /^migrations\/(([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql$/

// Mirrors the runner's nativeAppendedMigrations: existing migration files stay
// identical; new ones are contiguous versions after the current head, each with
// a matching up and down script. Returns the appended identifiers in order.
export function assertAppendOnlyMigrations(previous, candidate) {
  const migrations = (manifest) => new Map(manifest.files.filter((file) => file.path.startsWith('migrations/')).map((file) => [file.path, file]))
  const before = migrations(previous), after = migrations(candidate)
  for (const [name, file] of before) {
    if (JSON.stringify(after.get(name)) !== JSON.stringify(file)) throw new Error(`existing migration changed or removed: ${name}`)
  }
  let head = 0
  for (const name of before.keys()) {
    const match = migrationFile.exec(name)
    if (match) head = Math.max(head, Number(match[2]))
  }
  const added = new Map()
  for (const [name, file] of after) {
    if (before.has(name)) continue
    const match = migrationFile.exec(name)
    if (!match || match[1].length > 96 || file.mode !== 0o644 || file.bytes < 1) throw new Error(`invalid new migration file: ${name}`)
    const version = Number(match[2])
    if (version <= head) throw new Error(`new migration is not after the current head ${head}: ${name}`)
    const pair = added.get(version) ?? {}
    pair[match[3]] = match[1]
    added.set(version, pair)
  }
  if (added.size > 64) throw new Error('too many appended migrations')
  const applied = []
  for (let version = head + 1; version <= head + added.size; version++) {
    const pair = added.get(version)
    if (!pair?.up || pair.up !== pair.down) throw new Error(`appended migration ${version} needs matching up and down scripts with contiguous numbering`)
    applied.push(pair.up)
  }
  return applied
}

const clickHouseScript = 'clickhouse/configure-clickhouse.py'
const clickHouseMigration = /^clickhouse\/migrations\/(([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*)\.up\.sql$/

// Every release carries its ClickHouse migrations (001..N, up scripts only) and
// the helper that ledgers and applies them; the native runner runs that helper
// before the release's control-api starts.
// The root recovery runbook (docs/runbooks/platform-admin-recovery.md) ships as
// one manifest-owned file, docs/platform-admin-recovery.md, so a host without
// any working admin login can read the exact steps of its installed version
// (runner nativeOwnedContent allows exactly this path to change on upgrade).
export const nativeRecoveryRunbook = 'docs/platform-admin-recovery.md'
export function copyNativeRecoveryRunbook(source, release) {
  const input = path.join(source, 'docs/runbooks/platform-admin-recovery.md'), stat = fs.lstatSync(input, { throwIfNoEntry: false })
  if (!stat?.isFile() || stat.nlink !== 1 || stat.size < 1) throw new Error('release must include the platform admin recovery runbook')
  fs.rmSync(path.join(release, nativeRecoveryRunbook), { force: true })
  fs.mkdirSync(path.join(release, 'docs'), { recursive: true })
  fs.copyFileSync(input, path.join(release, nativeRecoveryRunbook), fs.constants.COPYFILE_EXCL)
  fs.chmodSync(path.join(release, nativeRecoveryRunbook), 0o644); fs.utimesSync(path.join(release, nativeRecoveryRunbook), 0, 0)
}

export function copyNativeClickHouse(source, release) {
  const directory = path.join(source, 'infra/clickhouse/migrations'), script = path.join(source, 'scripts/native-runtime/configure-clickhouse.py')
  const names = fs.readdirSync(directory).filter((name) => name.endsWith('.up.sql')).sort()
  if (!names.length || names.some((name, index) => !clickHouseMigration.test(`clickhouse/migrations/${name}`) || Number(name.slice(0, 3)) !== index + 1)) {
    throw new Error('ClickHouse migrations must be contiguous from 001')
  }
  fs.rmSync(path.join(release, 'clickhouse'), { recursive: true, force: true })
  fs.mkdirSync(path.join(release, 'clickhouse/migrations'), { recursive: true })
  for (const [input, output] of [[script, clickHouseScript], ...names.map((name) => [path.join(directory, name), `clickhouse/migrations/${name}`])]) {
    const stat = fs.lstatSync(input)
    if (!stat.isFile() || stat.nlink !== 1 || stat.size < 1) throw new Error('ClickHouse release input must be a regular non-empty file')
    fs.copyFileSync(input, path.join(release, output), fs.constants.COPYFILE_EXCL)
  }
}

// Mirrors the runner's nativeAppendedClickHouseMigrations: applied ClickHouse
// migrations stay byte-identical and new ones are appended contiguously.
export function assertAppendOnlyClickHouse(previous, candidate) {
  const inventory = (manifest) => manifest.files.filter((file) => file.path.startsWith('clickhouse/migrations/'))
  const before = inventory(previous), after = inventory(candidate)
  if (previous.files.some((file) => file.path === clickHouseScript) && !candidate.files.some((file) => file.path === clickHouseScript)) {
    throw new Error('ClickHouse migration helper removed')
  }
  after.forEach((file, index) => {
    const match = clickHouseMigration.exec(file.path)
    if (!match || Number(match[2]) !== index + 1 || file.mode !== 0o644 || file.bytes < 1) throw new Error(`invalid ClickHouse migration: ${file.path}`)
  })
  before.forEach((file, index) => {
    if (JSON.stringify(after[index]) !== JSON.stringify(file)) throw new Error(`applied ClickHouse migration changed or removed: ${file.path}`)
  })
  return after.slice(before.length).map((file) => clickHouseMigration.exec(file.path)[1])
}

const versionParts = (value) => value.split('.').map(Number)
const compareStable = (left, right) => {
  const [a, b] = [versionParts(left), versionParts(right)]
  for (let index = 0; index < 3; index++) if (a[index] !== b[index]) return a[index] - b[index]
  return 0
}

// Schema gate facts the release registration sends to the license service
// (control_schema_head / rollback_min_version): the highest control-api
// migration in the package, and the lowest version it may safely roll back to.
// Without rollbackMinVersion the release is not reversible across schema changes.
export function nativeSchemaGateFacts(manifest, rollbackMinVersion) {
  let head = 0
  for (const file of manifest.files) {
    const match = migrationFile.exec(file.path)
    if (match) head = Math.max(head, Number(match[2]))
  }
  if (head < 1 || head > 999) throw new Error('release has no control-api migration head')
  const facts = { control_schema_head: head }
  if (rollbackMinVersion !== undefined) {
    if (!stableVersion.test(rollbackMinVersion) || compareStable(rollbackMinVersion, manifest.version) >= 0) {
      throw new Error('rollback minimum version must be a stable version below the release version')
    }
    facts.rollback_min_version = rollbackMinVersion
  }
  return facts
}

export function preserveNativeWebFiles(previousRelease, release, files) {
  for (const file of files.filter((item) => item.path.startsWith('static/web/'))) {
    const target = path.join(release, file.path)
    if (file.path === 'static/web/runtime-config.js') {
      fs.copyFileSync(path.join(previousRelease, file.path), target)
    } else if (!fs.existsSync(target)) {
      fs.mkdirSync(path.dirname(target), { recursive: true })
      fs.copyFileSync(path.join(previousRelease, file.path), target, fs.constants.COPYFILE_EXCL)
    } else if (file.path.startsWith('static/web/assets/') && sha256(fs.readFileSync(target)) !== file.sha256) {
      throw new Error(`immutable asset name collision: ${file.path}`)
    }
  }
  const runtimeScript = /<script\b[^>]*\bsrc\s*=\s*["'](?:\/dashboard)?\/runtime-config\.js["'][^>]*>/i
  if (runtimeScript.test(fs.readFileSync(path.join(previousRelease, 'static/web/index.html'), 'utf8')) &&
      !runtimeScript.test(fs.readFileSync(path.join(release, 'static/web/index.html'), 'utf8'))) {
    throw new Error('candidate entry must preserve the verified runtime-config integration')
  }
}

export function buildNativeRelease(options) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const { commit, remoteRef, previousRelease, outputDir: requestedOutputDir, version, arch, siteKey, allowEmptySiteKey, keyID, previousArtifactPublicKeyPath, rollbackMinVersion } = options
  if (!objectID.test(commit) || !/^refs\/heads\/[a-zA-Z0-9_./-]+$/.test(remoteRef ?? '') ||
      !stableVersion.test(version) || !['amd64', 'arm64'].includes(arch) ||
      !path.isAbsolute(previousRelease ?? '') || !path.isAbsolute(requestedOutputDir ?? '') ||
      (!siteKey && !allowEmptySiteKey) || keyID !== undefined && (typeof keyID !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(keyID)) ||
      rollbackMinVersion !== undefined && (!stableVersion.test(rollbackMinVersion) || compareStable(rollbackMinVersion, version) >= 0)) throw new Error('invalid build arguments; see docs/runbooks/native-standalone-release.md')
  if (!fs.lstatSync(previousRelease).isDirectory() || fs.realpathSync(previousRelease) !== path.resolve(previousRelease)) {
    throw new Error('previous release must be a canonical directory, not a symlink or ancestor alias')
  }
  const outputDir = path.join(fs.realpathSync(path.dirname(requestedOutputDir)), path.basename(requestedOutputDir))
  if (fs.existsSync(outputDir)) throw new Error('output directory already exists; refusing to overwrite')
  if (path.resolve(outputDir).startsWith(path.resolve(previousRelease) + path.sep)) {
    throw new Error('output directory must not modify the immutable previous release')
  }
  const verifyRemote = () => {
    const entries = run(root, 'git', ['ls-remote', '--exit-code', 'origin', remoteRef]).split('\n')
    if (entries.length !== 1 || entries[0] !== `${commit}\t${remoteRef}`) throw new Error('source commit is not the exact remote branch tip')
  }
  verifyRemote()
  const previous = JSON.parse(fs.readFileSync(path.join(previousRelease, 'release.manifest.json'), 'utf8'))
  if (![schema, signedSchema].includes(previous.schema) || previous.platform?.os !== 'linux' || previous.platform?.arch !== arch) {
    throw new Error('a verified native-format baseline of the same architecture is required; this is not a bootstrap installer')
  }
  if (previous.schema === signedSchema) {
    if (!keyID || !path.isAbsolute(previousArtifactPublicKeyPath ?? '')) throw new Error('signed baseline requires independent artifact trust and cannot downgrade to v1')
    const signatureFile = path.join(previousRelease, 'release.manifest.sig'), signatureStat = fs.lstatSync(signatureFile)
    if (!signatureStat.isFile() || signatureStat.nlink !== 1 || signatureStat.size > 128 || (signatureStat.mode & 0o7777) !== 0o644) throw new Error('invalid baseline signature file')
    verifyNativeManifestSignature(fs.readFileSync(path.join(previousRelease, 'release.manifest.json')), fs.readFileSync(signatureFile, 'utf8'), fs.readFileSync(previousArtifactPublicKeyPath))
  } else if (previous.key_id !== undefined) throw new Error('v1 baseline cannot contain a signing key')
  const previousFacts = createNativeManifest(previousRelease, {
    version: previous.version, built_at: previous.built_at, source: previous.source, platform: previous.platform, key_id: previous.key_id,
  })
  if (JSON.stringify(previousFacts.files) !== JSON.stringify(previous.files)) throw new Error('previous release hashes or file inventory do not match')
  if (previous.source.commit === commit) throw new Error('source is unchanged')
  const currentVersion = version.split('.').map(Number), oldVersion = previous.version.split('.').map(Number)
  const difference = currentVersion.findIndex((value, index) => value !== oldVersion[index])
  if (difference < 0 || currentVersion[difference] <= oldVersion[difference]) throw new Error('version must strictly increase')
  run(root, 'git', ['merge-base', '--is-ancestor', previous.source.commit, commit])
  const tree = run(root, 'git', ['rev-parse', `${commit}^{tree}`])
  const builtAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-package-')))
  try {
    const source = path.join(work, 'source'), release = path.join(work, 'release')
    fs.mkdirSync(source)
    // The validated baseline is copied intact. Only this build's owned components
    // are replaced inside this newly created temporary copy, never in the input.
    fs.cpSync(previousRelease, release, { recursive: true, dereference: false })
    if (!fs.lstatSync(release).isDirectory() ||
        JSON.stringify(createNativeManifest(release, previous).files) !== JSON.stringify(previousFacts.files)) {
      throw new Error('copied baseline must be an unchanged directory without links')
    }
    fs.unlinkSync(path.join(release, 'release.manifest.json'))
    if (previous.schema === signedSchema) fs.unlinkSync(path.join(release, 'release.manifest.sig'))
    fs.rmSync(path.join(release, 'static/web'), { recursive: true })
    fs.rmSync(path.join(release, 'migrations'), { recursive: true })
    fs.mkdirSync(path.join(release, 'migrations'))
    run(root, 'git', ['archive', '--format=tar', `--output=${path.join(work, 'source.tar')}`, commit])
    run(work, 'tar', ['-xf', path.join(work, 'source.tar'), '-C', source])
    // Same Web build inputs as the first-install builder: a chained release is also the first-install identity.
    const buildEnv = { ...process.env, CGO_ENABLED: '0', GOOS: 'linux', GOARCH: arch, GOENV: 'off', GOAMD64: 'v1',
      GOWORK: path.join(source, 'go.work'), VITE_API_BASE_URL: '', VITE_RELEASE: commit,
      VITE_PACKAGE_COMMERCE_ENABLED: 'true', VITE_TURNSTILE_SITE_KEY: siteKey ?? '' }
    delete buildEnv.GOFLAGS; delete buildEnv.GOEXPERIMENT
    const flags = `-s -w -X main.controlVersion=${version} -X main.controlSourceCommit=${commit} -X main.controlSourceTree=${tree} -X main.controlBuildTime=${builtAt}`
    run(source, 'go', ['build', '-trimpath', '-buildvcs=false', `-ldflags=${flags}`, '-o', path.join(release, 'bin/control-api'), './services/control-api/cmd/control-api'], buildEnv)
    run(source, 'go', ['build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', path.join(release, 'bin/agent-gateway'), './services/agent-gateway/cmd/agent-gateway'], buildEnv)
    run(source, 'pnpm', ['install', '--frozen-lockfile', '--filter', '@cdnca/web...'], buildEnv)
    run(source, 'pnpm', ['--filter', '@cdnca/web', 'build'], buildEnv)
    // Community edition: no public website (static/web/site); nginx then serves the console entry at /.
    fs.cpSync(path.join(source, 'apps/web/dist'), path.join(release, 'static/web'), { recursive: true, dereference: false })
    // The console serves /downloads/install-node.sh from the active release; refresh it from this
    // source before preserving older Web files, or upgrades keep handing out the previous installer.
    const nodeInstaller = path.join(source, 'scripts/install-node.sh')
    if (!fs.lstatSync(nodeInstaller, { throwIfNoEntry: false })?.isFile() || !fs.readFileSync(nodeInstaller, 'utf8').startsWith('#!/usr/bin/env bash\n')) {
      throw new Error('release must include the node installer')
    }
    fs.mkdirSync(path.join(release, 'static/web/downloads'), { recursive: true })
    fs.copyFileSync(nodeInstaller, path.join(release, 'static/web/downloads/install-node.sh'), fs.constants.COPYFILE_EXCL)
    // Billing integration PHP modules (ADR 0019): integrations/build.sh output, served at
    // /downloads/billing-bridge/ from the active release so an upgrade refreshes them.
    // A source tree without integrations/build.sh (older commits, test fixtures) ships none.
    if (fs.lstatSync(path.join(source, 'integrations/build.sh'), { throwIfNoEntry: false })?.isFile()) {
      run(path.join(source, 'integrations'), 'bash', ['build.sh'], buildEnv)
      fs.mkdirSync(path.join(release, 'static/web/downloads/billing-bridge'), { recursive: true })
      for (const name of ['cdnca-whmcs.zip', 'cdnca-zjmf.zip', 'cdnca-zjmf-v10.zip']) {
        fs.copyFileSync(path.join(source, 'integrations/dist', name), path.join(release, 'static/web/downloads/billing-bridge', name), fs.constants.COPYFILE_EXCL)
      }
    }
    preserveNativeWebFiles(previousRelease, release, previous.files)
    copyNativeRecoveryRunbook(source, release)
    for (const name of fs.readdirSync(path.join(source, 'services/control-api/migrations'))) {
      if (/^[0-9]{3}_[a-z0-9_]+\.(up|down)\.sql$/.test(name)) {
        const input = path.join(source, 'services/control-api/migrations', name)
        if (!fs.lstatSync(input).isFile()) throw new Error('migration must be a regular file')
        fs.copyFileSync(input, path.join(release, 'migrations', name), fs.constants.COPYFILE_EXCL)
      }
    }
    const normalize = (directory) => {
      for (const name of fs.readdirSync(directory)) {
        const filename = path.join(directory, name), stat = fs.lstatSync(filename)
        if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) throw new Error('non-regular release entry')
        if (stat.isDirectory()) normalize(filename)
        else { fs.chmodSync(filename, path.dirname(filename) === path.join(release, 'bin') ? 0o755 : 0o644); fs.utimesSync(filename, 0, 0) }
      }
    }
    copyNativeClickHouse(source, release)
    normalize(path.join(release, 'static/web'))
    normalize(path.join(release, 'migrations'))
    normalize(path.join(release, 'clickhouse'))
    for (const component of ['control-api', 'agent-gateway']) {
      const filename = path.join(release, 'bin', component)
      fs.chmodSync(filename, 0o755)
      fs.utimesSync(filename, 0, 0)
    }
    const manifest = createNativeManifest(release, { version, built_at: builtAt, key_id: keyID,
      source: { commit, tree, previous_commit: previous.source.commit }, platform: { os: 'linux', arch } })
    assertAppendOnlyMigrations(previous, manifest)
    assertAppendOnlyClickHouse(previous, manifest)
    verifyRemote()
    fs.writeFileSync(path.join(release, 'release.manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o644 })
    fs.utimesSync(path.join(release, 'release.manifest.json'), 0, 0)
    fs.writeFileSync(path.join(work, 'members'), ['release.manifest.json', ...manifest.files.map((file) => file.path)].join('\n') + '\n', { flag: 'wx' })
    fs.mkdirSync(outputDir, { mode: 0o700 })
    const archiveName = keyID ? 'native-management.unsigned.tar' : 'native-management.tar', archive = path.join(outputDir, archiveName)
    const ownership = run(work, 'tar', ['--version']).includes('bsdtar') ? ['--uid', '0', '--gid', '0', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    run(release, 'tar', ['--format=ustar', ...ownership, '-cf', archive, '-T', path.join(work, 'members')])
    const artifact = { schema: `cdnca.native-management.unsigned-build/v${keyID ? 2 : 1}`, source: manifest.source,
      version, built_at: builtAt, file: archiveName, sha256: sha256(fs.readFileSync(archive)), bytes: fs.statSync(archive).size,
      signing_required: true, schema_gate: nativeSchemaGateFacts(manifest, rollbackMinVersion) }
    fs.copyFileSync(path.join(release, 'release.manifest.json'), path.join(outputDir, 'release.manifest.json'), fs.constants.COPYFILE_EXCL)
    if (keyID) {
      fs.cpSync(release, path.join(outputDir, 'payload'), { recursive: true, dereference: false, errorOnExist: true })
      fs.writeFileSync(path.join(outputDir, 'release.signing-data'), Buffer.concat([Buffer.from(signedSchema + '\n'), fs.readFileSync(path.join(release, 'release.manifest.json'))]), { flag: 'wx', mode: 0o600 })
    }
    fs.writeFileSync(path.join(outputDir, 'build.json'), JSON.stringify(artifact, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
    return artifact
  } finally {
    fs.rmSync(work, { recursive: true, force: true })
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const keys = { '--source-commit': 'commit', '--remote-ref': 'remoteRef', '--previous-release': 'previousRelease',
      '--output-dir': 'outputDir', '--version': 'version', '--arch': 'arch', '--turnstile-site-key': 'siteKey',
      '--key-id': 'keyID', '--previous-artifact-public-key': 'previousArtifactPublicKeyPath',
      '--rollback-min-version': 'rollbackMinVersion' }
    const options = {}
    for (let index = 2; index < process.argv.length; index++) {
      const flag = process.argv[index]
      if (flag === '--allow-empty-turnstile-site-key' && !options.allowEmptySiteKey) { options.allowEmptySiteKey = true; continue }
      const key = keys[flag], value = process.argv[++index]
      if (!key || value === undefined || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
      options[key] = value
    }
    console.log(JSON.stringify(buildNativeRelease(options), null, 2))
  } catch (error) {
    console.error(`native release build: ${error.message}`)
    process.exitCode = 1
  }
}
