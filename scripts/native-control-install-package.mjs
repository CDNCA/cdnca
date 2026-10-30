#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { initialBaselineSemantics, verifyNativeManifestSignature } from './native-release-package.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const schema = 'cdnca.native-management.install/v1', signedSchema = 'cdnca.native-management.install/v2'
const objectID = /^[a-f0-9]{40}$/, maximum = 1 << 30, smallLimit = 8 << 20, binaryLimit = 285229182
const encode = (value) => JSON.stringify(value, null, 2) + '\n'
const sourcePaths = [
  'scripts/install-node.sh',
  'scripts/native-runtime/install-ubuntu-dependencies.sh', 'scripts/native-runtime/configure-clickhouse.py',
  'scripts/native-runtime/configure-nats.py', 'scripts/native-runtime/native-nats-profile.json',
  'scripts/native-runtime/install-rustfs.py', 'scripts/native-runtime/rustfs-1.0.1.json',
  'scripts/native-runtime/install-native-baseline.py', 'scripts/native-runtime/configure-control-runtime.py',
  'scripts/native-runtime/configure-certificate-runtime.py',
  'scripts/native-runtime/configure-native-upgrade.py', 'deploy/systemd/install-native-control-upgrade-runner.sh',
  // Every ClickHouse up migration of this source tree, not a fixed count; the
  // installer and configure-clickhouse.py require them contiguous from 001.
  ...fs.readdirSync(path.join(repository, 'infra/clickhouse/migrations')).filter((name) => name.endsWith('.up.sql')).sort()
    .map((name) => `infra/clickhouse/migrations/${name}`),
]
const payloadPaths = ['native-management.tar', 'release.manifest.json', 'control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server', 'NATS-LICENSE', 'cdnca-ed25519', 'source.bundle', ...sourcePaths].sort()
const signedPaths = payloadPaths.filter((name) => name !== 'source.bundle').concat('release.manifest.sig').sort()
const modes = Object.fromEntries(payloadPaths.map((name) => [name, ['native-management.tar', 'source.bundle'].includes(name)
  ? 0o600 : ['control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server', 'cdnca-ed25519'].includes(name) || name.endsWith('.sh') ? 0o755 : 0o644]))
modes['release.manifest.sig'] = 0o644
const limits = Object.fromEntries(payloadPaths.map((name) => [name, name === 'source.bundle' ? 512 << 20
  : ['native-management.tar', 'control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server'].includes(name) ? binaryLimit : smallLimit]))
limits['release.manifest.sig'] = 128

export function nativeControlInstallCommand(cwd, command, args, env = process.env) {
  try {
    return execFileSync(command, command === 'git' ? ['--no-replace-objects', '-c', 'gc.auto=0', ...args] : args, {
      cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 << 20, timeout: 120000,
    }).trim()
  } catch { throw new Error(`native install package command failed: ${command}`) }
}

export function nativeControlInstallFile(filename, limit) {
  if (fs.realpathSync(filename) !== filename) throw new Error('package input contains a link')
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK)
  try {
    const before = fs.fstatSync(descriptor)
    if (!before.isFile() || before.nlink !== 1) throw new Error('package input must be a regular file without links')
    if (before.size < 1 || before.size > limit) throw new Error('package file exceeds size limit')
    const hash = createHash('sha256'), buffer = Buffer.alloc(1 << 20)
    let bytes = 0, read
    while ((read = fs.readSync(descriptor, buffer, 0, buffer.length, null))) { bytes += read; hash.update(buffer.subarray(0, read)) }
    const after = fs.fstatSync(descriptor)
    if (bytes !== before.size || ['dev', 'ino', 'size', 'mode', 'nlink', 'mtimeMs', 'ctimeMs'].some((key) => before[key] !== after[key])) {
      throw new Error('package input changed while reading')
    }
    return { bytes, mode: before.mode & 0o7777, sha256: hash.digest('hex') }
  } finally { fs.closeSync(descriptor) }
}

export function createNativeControlInstallManifest(directory, metadata) {
  const selectedSchema = metadata.schema ?? schema, paths = selectedSchema === signedSchema ? signedPaths : payloadPaths
  if (![schema, signedSchema].includes(selectedSchema) || typeof metadata.key_id !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(metadata.key_id) ||
      typeof metadata.version !== 'string' || !/^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/.test(metadata.version) ||
      !Number.isFinite(Date.parse(metadata.built_at)) || new Date(metadata.built_at).toISOString().replace('.000Z', 'Z') !== metadata.built_at ||
      !['commit', 'tree'].every((key) => objectID.test(metadata.source?.[key])) ||
      metadata.source.previous_commit !== undefined && !objectID.test(metadata.source.previous_commit) ||
      metadata.source.commit === metadata.source.previous_commit || metadata.platform?.os !== 'linux' || metadata.platform?.arch !== 'amd64') {
    throw new Error('invalid install manifest metadata')
  }
  if (!fs.lstatSync(directory).isDirectory() || fs.realpathSync(directory) !== directory) throw new Error('unsafe payload directory')
  const names = [], walk = (relative = '') => {
    for (const name of fs.readdirSync(path.join(directory, relative))) {
      const member = relative ? `${relative}/${name}` : name, info = fs.lstatSync(path.join(directory, member))
      if (info.isDirectory() && paths.some((file) => file.startsWith(member + '/'))) walk(member)
      else {
        if (!info.isFile() || info.nlink !== 1) throw new Error('payload must contain regular files without links')
        if (!paths.includes(member)) throw new Error('unexpected payload inventory')
        if ((info.mode & 0o7777) !== modes[member]) throw new Error('unexpected payload mode')
        if (info.size < 1 || info.size > limits[member]) throw new Error('payload exceeds file size limit')
        names.push(member)
      }
    }
  }
  walk()
  if (JSON.stringify(names.sort()) !== JSON.stringify(paths)) throw new Error('missing payload inventory')
  // Include conservative USTAR metadata/padding overhead before hashing large files.
  if (names.reduce((total, name) => total + fs.statSync(path.join(directory, name)).size, 2 * smallLimit) > maximum) {
    throw new Error('outer package exceeds size limit')
  }
  const files = names.map((name) => ({ path: name, ...nativeControlInstallFile(path.join(directory, name), limits[name]) }))
  return { schema: selectedSchema, key_id: metadata.key_id, version: metadata.version, built_at: metadata.built_at,
    source: { commit: metadata.source.commit, tree: metadata.source.tree,
      ...(metadata.source.previous_commit === undefined ? {} : { previous_commit: metadata.source.previous_commit }) },
    platform: { os: 'linux', arch: 'amd64' }, files }
}

export function nativeControlInstallSource(commit, remoteRef) {
  if (!objectID.test(commit) || !/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(remoteRef ?? '')) throw new Error('invalid source arguments')
  const git = (...args) => nativeControlInstallCommand(repository, 'git', args)
  const check = () => {
    if (git('ls-remote', '--exit-code', 'origin', remoteRef) !== `${commit}\t${remoteRef}` || git('rev-parse', 'HEAD') !== commit) {
      throw new Error('source must equal HEAD and the exact pushed remote tip')
    }
  }
  check()
  if (git('rev-parse', '--is-shallow-repository') !== 'false' || git('rev-parse', `${commit}^{commit}`) !== commit) throw new Error('incomplete source repository')
  return { git, check, tree: git('rev-parse', `${commit}^{tree}`) }
}

export function verifyNativeControlInstallBundle(bundle, metadata, work) {
  nativeControlInstallFile(bundle, limits['source.bundle'])
  const bare = path.join(work, 'source.git'), source = path.join(work, 'source')
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_COUNT: '0', GIT_GRAFT_FILE: '/dev/null' }
  nativeControlInstallCommand(work, 'git', ['init', '--quiet', '--bare', '--template=', bare], env)
  const git = (...args) => nativeControlInstallCommand(bare, 'git', args, env)
  if (git('bundle', 'list-heads', bundle) !== `${metadata.source.commit} HEAD`) throw new Error('bundle must advertise only candidate HEAD')
  git('bundle', 'verify', bundle); git('bundle', 'unbundle', bundle)
  git('update-ref', 'HEAD', metadata.source.commit)
  if (git('rev-parse', `${metadata.source.commit}^{tree}`) !== metadata.source.tree ||
      git('fsck', '--full', '--no-reflogs', '--unreachable', '--no-progress') !== '') throw new Error('bundle contains invalid or unrelated objects')
  if (metadata.source.previous_commit !== undefined) git('merge-base', '--is-ancestor', metadata.source.previous_commit, metadata.source.commit)
  const treeEntries = git('ls-tree', '-r', metadata.source.commit).split('\n')
  if (treeEntries.some((entry) => !/^100(?:644|755) blob [a-f0-9]{40}\t/.test(entry))) {
    throw new Error('source tree contains links or unsupported objects')
  }
  fs.mkdirSync(source)
  git('-c', 'tar.umask=0022', 'archive', '--format=tar', `--output=${path.join(work, 'source.tar')}`, metadata.source.commit)
  nativeControlInstallCommand(work, 'tar', ['-xpf', path.join(work, 'source.tar'), '-C', source])
  // Committed export-ignore/export-subst attributes must not silently make an
  // archive differ from the source tree whose identity we are attesting.
  for (const entry of treeEntries) {
    const [, mode, blob, name] = /^(100(?:644|755)) blob ([a-f0-9]{40})\t(.+)$/.exec(entry)
    const filename = path.join(source, name), stat = fs.lstatSync(filename)
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > (512 << 20) || (stat.mode & 0o7777) !== (Number.parseInt(mode, 8) & 0o777)) throw new Error('archived source file metadata differs from Git tree')
    const bytes = fs.readFileSync(filename)
    if (createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') !== blob) throw new Error('archived source bytes differ from Git blob')
  }
  return source
}

function buildNativeAnalyticsHistoryBootstrap(source, destination) {
  if (fs.lstatSync(destination, { throwIfNoEntry: false })) throw new Error('bootstrap output already exists')
  const env = { ...process.env, GOWORK: 'off', GOENV: 'off', GOOS: 'linux', GOARCH: 'amd64', GOAMD64: 'v1', CGO_ENABLED: '0' }
  delete env.GOFLAGS; delete env.GOEXPERIMENT
  nativeControlInstallCommand(path.join(source, 'services/control-api'), 'go',
    ['build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-o', destination, './cmd/analytics-history-bootstrap'], env)
  fs.chmodSync(destination, 0o755)
  return nativeControlInstallFile(destination, binaryLimit)
}

export function buildNativeUpgradeRunner(source, destination, arch) {
  if (fs.lstatSync(destination, { throwIfNoEntry: false }) || !['amd64', 'arm64'].includes(arch)) throw new Error('invalid runner build output or platform')
  const env = { ...process.env, GOWORK: 'off', GOENV: 'off', GOOS: 'linux', GOARCH: arch, GOAMD64: 'v1', CGO_ENABLED: '0' }
  delete env.GOFLAGS; delete env.GOEXPERIMENT
  nativeControlInstallCommand(path.join(source, 'services/control-api'), 'go',
    ['build', '-trimpath', '-buildvcs=false', '-mod=readonly', '-ldflags=-s -w', '-o', destination, './cmd/control-upgrade-runner'], env)
  fs.chmodSync(destination, 0o755)
  return nativeControlInstallFile(destination, binaryLimit)
}

// Static Ed25519 tool: one reproducible build (tools/ed25519-tool/build.sh) whose
// SHA-256 must equal the pin in the committed installers before it can ship.
export function nativeEd25519ToolPin(source) {
  const pin = /^readonly CDNCA_ED25519_TOOL_SHA256="([a-f0-9]{64})"$/m.exec(fs.readFileSync(path.join(source, 'scripts/install-node.sh'), 'utf8'))?.[1]
  if (!pin) throw new Error('installer Ed25519 tool pin is missing')
  return pin
}

export function buildNativeEd25519Tool(source, destination) {
  if (fs.lstatSync(destination, { throwIfNoEntry: false })) throw new Error('Ed25519 tool output already exists')
  const tool = path.join(source, 'tools/ed25519-tool')
  nativeControlInstallCommand(tool, 'sh', [path.join(tool, 'build.sh'), destination])
  fs.chmodSync(destination, 0o755)
  const built = nativeControlInstallFile(destination, smallLimit)
  if (built.sha256 !== nativeEd25519ToolPin(source)) throw new Error('Ed25519 tool build differs from the installer pin')
  return built
}

function verifyNativeNATSArtifacts(payload, source) {
  const profile = JSON.parse(fs.readFileSync(path.join(source, 'scripts/native-runtime/native-nats-profile.json'), 'utf8'))
  if (profile.server_version !== '2.12.15-cdnca.1') throw new Error('unsupported NATS dependency version')
  const pins = profile.server_artifact
  for (const [name, digest, bytes] of [['nats-server', pins?.sha256, pins?.bytes],
    ['NATS-LICENSE', pins?.license_sha256, pins?.license_bytes]]) {
    if (!/^[a-f0-9]{64}$/.test(digest ?? '') || !Number.isSafeInteger(bytes) || bytes < 1) throw new Error('invalid NATS dependency pin')
    const actual = nativeControlInstallFile(path.join(payload, name), limits[name])
    if (actual.sha256 !== digest || actual.bytes !== bytes) throw new Error('NATS dependency differs from exact archived source pin')
  }
}

function verifyNativeControlInstallBaseline(payload, metadata, source, artifactPublicKeyPath) {
  const signed = metadata.schema === signedSchema
  nativeControlInstallFile(path.join(payload, 'release.manifest.json'), smallLimit)
  const raw = fs.readFileSync(path.join(payload, 'release.manifest.json'), 'utf8'), sidecar = JSON.parse(raw)
  if (encode(sidecar) !== raw || sidecar.schema !== `cdnca.native-management.release/v${signed ? 2 : 1}` ||
      sidecar.version !== metadata.version || sidecar.built_at !== metadata.built_at ||
      JSON.stringify(sidecar.source) !== JSON.stringify(metadata.source) || JSON.stringify(sidecar.platform) !== JSON.stringify(metadata.platform)) {
    throw new Error('native baseline sidecar does not match install metadata')
  }
  if (signed) {
    if (!path.isAbsolute(artifactPublicKeyPath ?? '')) throw new Error('independent artifact trust is required')
    nativeControlInstallFile(fs.realpathSync(artifactPublicKeyPath), smallLimit)
    nativeControlInstallFile(path.join(payload, 'release.manifest.sig'), 128)
    verifyNativeManifestSignature(raw, fs.readFileSync(path.join(payload, 'release.manifest.sig'), 'utf8'), fs.readFileSync(artifactPublicKeyPath))
  }
  verifyNativeReleaseMigrations(sidecar, source)
  verifyNativeReleaseClickHouse(sidecar, source)
  verifyNativeNATSArtifacts(payload, source)
  if (nativeControlInstallFile(path.join(payload, 'cdnca-ed25519'), smallLimit).sha256 !== nativeEd25519ToolPin(source)) {
    throw new Error('Ed25519 tool differs from the installer pin')
  }
  for (const name of ['control-upgrade-runner', 'analytics-history-bootstrap', 'nats-server']) {
    const binary = path.join(payload, name)
    nativeControlInstallFile(binary, binaryLimit)
    const descriptor = fs.openSync(binary, 'r'), header = Buffer.alloc(64)
    try {
      if (fs.readSync(descriptor, header, 0, 64, 0) !== 64 || !header.subarray(0, 7).equals(Buffer.from('\x7fELF\x02\x01\x01', 'binary')) ||
          ![2, 3].includes(header.readUInt16LE(16)) || header.readUInt16LE(18) !== 62) throw new Error('installer binary must be Linux ELF64 amd64')
    } finally { fs.closeSync(descriptor) }
  }
  const bootstrap = buildNativeAnalyticsHistoryBootstrap(source, path.join(source, 'analytics-history-bootstrap.verify'))
  if (bootstrap.sha256 !== nativeControlInstallFile(path.join(payload, 'analytics-history-bootstrap'), binaryLimit).sha256) {
    throw new Error('analytics bootstrap differs from exact archived source')
  }
  const runner = buildNativeUpgradeRunner(source, path.join(source, 'control-upgrade-runner.verify'), sidecar.platform.arch)
  if (runner.sha256 !== nativeControlInstallFile(path.join(payload, 'control-upgrade-runner'), binaryLimit).sha256) {
    throw new Error('upgrade runner differs from exact archived source')
  }
  validateNativeReleaseWithGo(path.join(payload, 'native-management.tar'), sidecar, source, artifactPublicKeyPath)
  for (const name of sourcePaths) {
    if (nativeControlInstallFile(path.join(source, name), smallLimit).sha256 !== nativeControlInstallFile(path.join(payload, name), smallLimit).sha256) {
      throw new Error('helper differs from exact archived source')
    }
  }
}

// The release's own CH copy (what the upgrade runner applies) must equal the
// archived source byte for byte, exactly like the install helper copy.
export function verifyNativeReleaseClickHouse(manifest, source) {
  const directory = path.join(source, 'infra/clickhouse/migrations')
  const expected = [['clickhouse/configure-clickhouse.py', path.join(source, 'scripts/native-runtime/configure-clickhouse.py')],
    ...fs.readdirSync(directory).filter((name) => name.endsWith('.up.sql')).sort().map((name) => [`clickhouse/migrations/${name}`, path.join(directory, name)])]
  const files = manifest.files.filter((file) => file.path.startsWith('clickhouse/'))
  if (!isDeepStrictEqual(files.map((file) => file.path), expected.map(([name]) => name))) throw new Error('ClickHouse release inventory mismatch')
  for (const [index, [, filename]] of expected.entries()) {
    const actual = nativeControlInstallFile(filename, smallLimit), file = files[index]
    if (file.mode !== 0o644 || file.sha256 !== actual.sha256 || file.bytes !== actual.bytes) throw new Error('ClickHouse release file differs from exact archived source')
  }
}

export function verifyNativeReleaseMigrations(manifest, source) {
  const directory = path.join(source, 'services/control-api/migrations')
  if (!fs.lstatSync(directory).isDirectory()) throw new Error('migration source must be a directory')
  const names = fs.readdirSync(directory).filter((name) => /^[0-9]{3}_[a-z0-9_]+\.(up|down)\.sql$/.test(name)).sort()
  const migrations = manifest.files.filter((file) => file.path.startsWith('migrations/'))
  if (!names.length || names.some((name) => !names.includes(name.replace(/\.(up|down)\.sql$/, (_, direction) => `.${direction === 'up' ? 'down' : 'up'}.sql`))) ||
      !isDeepStrictEqual(migrations.map((file) => file.path).sort(), names.map((name) => 'migrations/' + name))) throw new Error('migration source inventory mismatch')
  for (const file of migrations) {
    const actual = nativeControlInstallFile(path.join(directory, file.path.slice('migrations/'.length)), smallLimit)
    if (actual.mode !== 0o644 || file.mode !== 0o644 || file.sha256 !== actual.sha256 || file.bytes !== actual.bytes) throw new Error('migration differs from exact archived source')
  }
}

export function validateNativeReleaseWithGo(archivePath, manifest, source, artifactPublicKeyPath) {
  const archive = nativeControlInstallFile(archivePath, binaryLimit), signed = manifest.schema === 'cdnca.native-management.release/v2'
  const module = path.join(source, 'services/control-api'), caller = fs.mkdtempSync(path.join(module, 'cmd/native-install-verify-'))
  if (signed) fs.writeFileSync(path.join(caller, 'trust.json'), encode({ version: 1, keys: [{ key_id: manifest.key_id, public_key_pem: fs.readFileSync(artifactPublicKeyPath, 'utf8') }] }), { flag: 'wx', mode: 0o600 })
  fs.writeFileSync(path.join(caller, 'main.go'), `package main
import ("encoding/json"; "os"; "strconv"; u "github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade")
func main() {
 n, e := strconv.ParseInt(os.Args[4], 10, 64); if e != nil { os.Exit(1) }
 ${signed ? 'b, e := os.ReadFile(os.Args[6]); if e != nil { os.Exit(1) }; keys, e := u.DecodeNativeArtifactTrust(b); if e != nil { os.Exit(1) }' : ''}
 m, e := u.${signed ? 'ValidateSignedNativeReleaseArchive' : 'ValidateNativeReleaseArchive'}(os.Args[1], u.Artifact{Version:os.Args[2], Digest:os.Args[3], Size:n}, u.NativePlatform{OS:"linux", Arch:os.Args[5]}${signed ? ', keys' : ''})
 if e != nil { os.Exit(1) }; if json.NewEncoder(os.Stdout).Encode(m) != nil { os.Exit(1) }
}
`, { flag: 'wx', mode: 0o600 })
  const env = { ...process.env, GOWORK: 'off', GOENV: 'off', CGO_ENABLED: '0' }
  delete env.GOOS; delete env.GOARCH; delete env.GOFLAGS; delete env.GOEXPERIMENT
  const actual = JSON.parse(nativeControlInstallCommand(module, 'go', ['run', '-mod=readonly', './cmd/' + path.basename(caller),
    archivePath, manifest.version, archive.sha256, String(archive.bytes), manifest.platform.arch, ...(signed ? [path.join(caller, 'trust.json')] : [])], env))
  if (!isDeepStrictEqual(actual, manifest)) throw new Error('Go-validated native manifest differs from sidecar')
}

export function prepareNativeControlInstallPackage({ commit, remoteRef, initialBuildDir, natsBuildDir, keyID, outputDir: requestedOutput, artifactPublicKeyPath }) {
  if (!path.isAbsolute(initialBuildDir ?? '') || !path.isAbsolute(natsBuildDir ?? '') || !path.isAbsolute(requestedOutput ?? '') ||
      !fs.lstatSync(initialBuildDir).isDirectory() || !fs.lstatSync(natsBuildDir).isDirectory()) throw new Error('invalid package paths')
  const initial = fs.realpathSync(initialBuildDir), output = path.join(fs.realpathSync(path.dirname(requestedOutput)), path.basename(requestedOutput))
  if (fs.lstatSync(output, { throwIfNoEntry: false })) throw new Error('output exists; refusing to overwrite')
  const origin = nativeControlInstallSource(commit, remoteRef)
  nativeControlInstallFile(path.join(initial, 'build.json'), smallLimit)
  const build = JSON.parse(fs.readFileSync(path.join(initial, 'build.json'), 'utf8'))
  const signed = build.schema === 'cdnca.native-management.signed-build/v2', paths = signed ? signedPaths : payloadPaths
  const metadata = { schema: signed ? signedSchema : schema, key_id: keyID, version: build.version, built_at: build.built_at, source: build.source, platform: { os: 'linux', arch: 'amd64' } }
  // Two accepted inner inputs: the first-native-baseline build (carries its own runner), or a signed
  // release-chain build from native-release-package.mjs (no lineage markers, no runner). The chain
  // build is the same artifact the native runner upgrades to, so each version has one identity; its
  // runner is compiled here from the verified source bundle and still reproduced again below.
  const firstInstall = build.installation_mode === 'first-native-baseline'
  // An initial baseline (native-initial-release-package.mjs --baseline) names no predecessor.
  const baseline = firstInstall && build.source?.previous_commit === undefined
  if (![ 'cdnca.native-management.unsigned-build/v1', 'cdnca.native-management.signed-build/v2' ].includes(build.schema) ||
      (firstInstall ? build.previous_source_semantics !== (baseline ? initialBaselineSemantics : 'release-lineage-not-host-deployment') ||
        baseline && (build.schema_gate?.control_schema_head === undefined || build.schema_gate.rollback_min_version !== undefined) ||
        build.runner?.file !== 'control-upgrade-runner' ||
        build.runner.version !== build.version || build.runner.signing_required !== true ||
        JSON.stringify(build.runner.source) !== JSON.stringify({ commit, tree: origin.tree }) ||
        JSON.stringify(build.runner.platform) !== JSON.stringify(metadata.platform)
        : !signed || build.installation_mode !== undefined || build.previous_source_semantics !== undefined || build.runner !== undefined) ||
      build.signing_required !== !signed ||
      build.source?.commit !== commit || build.source?.tree !== origin.tree || !baseline && !objectID.test(build.source?.previous_commit) ||
      build.source.previous_commit === commit || build.file !== 'native-management.tar') throw new Error('initial build provenance mismatch')
  if (!baseline) origin.git('merge-base', '--is-ancestor', build.source.previous_commit, commit)
  const inherited = [['native-management.tar', build], ...(firstInstall ? [['control-upgrade-runner', build.runner]] : [])]
  for (const [name, expected] of inherited) {
    const actual = nativeControlInstallFile(path.join(initial, name), binaryLimit)
    if (actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) throw new Error('initial artifact digest mismatch')
  }
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-control-install-package-')))
  try {
    const payload = path.join(work, 'payload'); fs.mkdirSync(payload)
    for (const name of ['native-management.tar', 'release.manifest.json', ...(firstInstall ? ['control-upgrade-runner'] : []), ...(signed ? ['release.manifest.sig'] : [])]) {
      nativeControlInstallFile(path.join(initial, name), limits[name])
      fs.copyFileSync(path.join(initial, name), path.join(payload, name), fs.constants.COPYFILE_EXCL)
      fs.chmodSync(path.join(payload, name), modes[name])
    }
    const bundle = path.join(signed ? work : payload, 'source.bundle')
    origin.git('bundle', 'create', bundle, 'HEAD')
    fs.chmodSync(bundle, 0o600)
    const source = verifyNativeControlInstallBundle(bundle, metadata, work)
    for (const [input, name] of [['nats-server-2.12.15-cdnca.1', 'nats-server'], ['NATS-LICENSE', 'NATS-LICENSE']]) {
      const filename = path.join(fs.realpathSync(natsBuildDir), input)
      nativeControlInstallFile(filename, limits[name])
      fs.copyFileSync(filename, path.join(payload, name), fs.constants.COPYFILE_EXCL)
      fs.chmodSync(path.join(payload, name), modes[name])
    }
    for (const name of sourcePaths) {
      nativeControlInstallFile(path.join(source, name), smallLimit)
      fs.mkdirSync(path.dirname(path.join(payload, name)), { recursive: true })
      fs.copyFileSync(path.join(source, name), path.join(payload, name), fs.constants.COPYFILE_EXCL); fs.chmodSync(path.join(payload, name), modes[name])
    }
    buildNativeAnalyticsHistoryBootstrap(source, path.join(payload, 'analytics-history-bootstrap'))
    buildNativeEd25519Tool(source, path.join(payload, 'cdnca-ed25519'))
    if (!firstInstall) buildNativeUpgradeRunner(source, path.join(payload, 'control-upgrade-runner'), metadata.platform.arch)
    const manifest = createNativeControlInstallManifest(payload, metadata)
    for (const [name, expected] of inherited) {
      const actual = manifest.files.find((file) => file.path === name)
      if (actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) throw new Error('initial artifact changed during staging')
    }
    verifyNativeControlInstallBaseline(payload, manifest, source, artifactPublicKeyPath)
    origin.check()
    fs.mkdirSync(output, { mode: 0o700 })
    fs.cpSync(payload, path.join(output, 'payload'), { recursive: true, dereference: false, errorOnExist: true })
    for (const name of paths) {
      const filename = path.join(output, 'payload', name), info = fs.lstatSync(filename)
      if (!info.isFile() || info.nlink !== 1) throw new Error('copied payload contains links')
      fs.chmodSync(filename, modes[name])
    }
    if (encode(createNativeControlInstallManifest(path.join(output, 'payload'), metadata)) !== encode(manifest)) throw new Error('payload changed while copying')
    const raw = Buffer.from(encode(manifest)), digest = createHash('sha256').update(raw).digest('hex')
    fs.writeFileSync(path.join(output, 'install.manifest.json'), raw, { flag: 'wx', mode: 0o644 })
    fs.chmodSync(path.join(output, 'install.manifest.json'), 0o644)
    fs.writeFileSync(path.join(output, 'install.signing-data'), Buffer.concat([Buffer.from(manifest.schema + '\n'), raw]), { flag: 'wx', mode: 0o600 })
    const result = { schema: `cdnca.native-management.install.unsigned-build/v${signed ? 2 : 1}`, source: manifest.source,
      version: manifest.version, manifest_sha256: digest, signing_required: true, distribution: signed ? 'public-signed-no-source' : 'private-ssh-test-only' }
    fs.writeFileSync(path.join(output, 'build.json'), encode(result), { flag: 'wx', mode: 0o600 })
    return result
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

export function finalizeNativeControlInstallPackage({ buildDir, remoteRef, signaturePath, publicKeyPath, artifactPublicKeyPath }) {
  if (![buildDir, signaturePath, publicKeyPath].every((name) => path.isAbsolute(name ?? '')) || !fs.lstatSync(buildDir).isDirectory()) throw new Error('invalid finalization paths')
  const build = fs.realpathSync(buildDir), archive = path.join(build, 'cdnca-control-native.tar'), sums = path.join(build, 'SHA256SUMS')
  if ([archive, sums].some((name) => fs.lstatSync(name, { throwIfNoEntry: false }))) throw new Error('output exists; refusing to overwrite')
  nativeControlInstallFile(path.join(build, 'install.manifest.json'), smallLimit)
  const raw = fs.readFileSync(path.join(build, 'install.manifest.json')), manifest = JSON.parse(raw)
  if (![schema, signedSchema].includes(manifest.schema)) throw new Error('invalid install manifest schema')
  const signed = manifest.schema === signedSchema, paths = signed ? signedPaths : payloadPaths, domain = Buffer.from(manifest.schema + '\n')
  nativeControlInstallFile(fs.realpathSync(signaturePath), 1024); nativeControlInstallFile(fs.realpathSync(publicKeyPath), smallLimit)
  const encoded = fs.readFileSync(signaturePath, 'utf8').trim(), pem = fs.readFileSync(publicKeyPath, 'utf8')
  if (!/^[A-Za-z0-9+/]{86}==$/.test(encoded) || Buffer.from(encoded, 'base64').toString('base64') !== encoded || !pem.startsWith('-----BEGIN PUBLIC KEY-----\n')) throw new Error('invalid external signature or public key encoding')
  const key = createPublicKey(pem)
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.concat([domain, raw]), key, Buffer.from(encoded, 'base64'))) throw new Error('invalid external signature')
  const payload = path.join(build, 'payload')
  if (encode(createNativeControlInstallManifest(payload, manifest)) !== raw.toString('utf8')) throw new Error('manifest or payload changed after signing')
  const origin = nativeControlInstallSource(manifest.source.commit, remoteRef)
  if (origin.tree !== manifest.source.tree) throw new Error('source tree mismatch')
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-control-install-finalize-')))
  try {
    const staging = path.join(work, 'payload'); fs.cpSync(payload, staging, { recursive: true, dereference: false })
    for (const name of paths) {
      const filename = path.join(staging, name), info = fs.lstatSync(filename)
      if (!info.isFile() || info.nlink !== 1) throw new Error('copied payload contains links')
      fs.chmodSync(filename, modes[name])
    }
    if (encode(createNativeControlInstallManifest(staging, manifest)) !== raw.toString('utf8')) throw new Error('payload changed during finalization')
    const bundle = path.join(signed ? work : staging, 'source.bundle')
    if (signed) { origin.git('bundle', 'create', bundle, 'HEAD'); fs.chmodSync(bundle, 0o600) }
    const source = verifyNativeControlInstallBundle(bundle, manifest, work)
    verifyNativeControlInstallBaseline(staging, manifest, source, artifactPublicKeyPath)
    if (encode(createNativeControlInstallManifest(staging, manifest)) !== raw.toString('utf8')) throw new Error('payload changed during validation')
    fs.writeFileSync(path.join(staging, 'install.manifest.json'), raw, { flag: 'wx', mode: 0o644 })
    fs.writeFileSync(path.join(staging, 'install.manifest.sig'), encoded + '\n', { flag: 'wx', mode: 0o644 })
    const names = ['install.manifest.json', 'install.manifest.sig', ...paths]
    for (const name of names) { fs.chmodSync(path.join(staging, name), modes[name] ?? 0o644); fs.utimesSync(path.join(staging, name), 0, 0) }
    fs.writeFileSync(path.join(work, 'members'), names.join('\n') + '\n', { flag: 'wx' })
    const ownership = nativeControlInstallCommand(work, 'tar', ['--version']).includes('bsdtar')
      ? ['--uid', '0', '--gid', '0', '--uname', '', '--gname', '', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    const temporary = path.join(work, 'install.tar')
    nativeControlInstallCommand(staging, 'tar', ['--format=ustar', ...ownership, '-cf', temporary, '-T', path.join(work, 'members')], { ...process.env, COPYFILE_DISABLE: '1' })
    const result = nativeControlInstallFile(temporary, maximum)
    origin.check()
    fs.copyFileSync(temporary, archive, fs.constants.COPYFILE_EXCL); fs.chmodSync(archive, 0o600)
    if (!isDeepStrictEqual(nativeControlInstallFile(archive, maximum), { ...result, mode: 0o600 })) throw new Error('archive changed while copying')
    fs.writeFileSync(sums, `${result.sha256}  cdnca-control-native.tar\n`, { flag: 'wx', mode: 0o644 })
    return { schema: manifest.schema, source: manifest.source, version: manifest.version, sha256: result.sha256, bytes: result.bytes }
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

function nativeControlInstallCLI(args) {
  const command = args[0], options = {}
  const keys = { '--source-commit': 'commit', '--remote-ref': 'remoteRef', '--initial-build-dir': 'initialBuildDir',
    '--nats-build-dir': 'natsBuildDir', '--key-id': 'keyID', '--output-dir': 'outputDir', '--build-dir': 'buildDir', '--signature': 'signaturePath', '--public-key': 'publicKeyPath',
    '--artifact-public-key': 'artifactPublicKeyPath' }
  for (let index = 1; index < args.length; index += 2) {
    const key = keys[args[index]], value = args[index + 1]
    if (!key || !value || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
    options[key] = value
  }
  if (command !== 'prepare' && command !== 'finalize') throw new Error('expected prepare or finalize')
  return command === 'prepare' ? prepareNativeControlInstallPackage(options) : finalizeNativeControlInstallPackage(options)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(encode(nativeControlInstallCLI(process.argv.slice(2)))) }
  catch (error) { console.error(`native control install package: ${error.message}`); process.exitCode = 1 }
}
