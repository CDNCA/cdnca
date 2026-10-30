#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { copyNativeClickHouse, copyNativeRecoveryRunbook, createNativeManifest, initialBaselineSemantics, nativeSchemaGateFacts } from './native-release-package.mjs'

// This one-time predecessor is published release lineage, not a claim that a
// blank host ran it. Subsequent upgrades must use the existing baseline builder.
// --baseline instead builds an initial release with no predecessor at all
// (1.0.35: fresh installs only, no upgrade path from any earlier version).
const predecessor = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'
const predecessorTree = '110d3367f0aa9f7f96f1f7c3739f551cbdfdc397'
const objectID = /^[0-9a-f]{40}$/
const stableVersion = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/
const migrationName = /^[0-9]{3}_[a-z0-9_]+\.(up|down)\.sql$/
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

function runInitialNativeCommand(cwd, command, args, env = process.env) {
  return execFileSync(command, command === 'git' ? ['--no-replace-objects', ...args] : args, {
    cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 16 << 20,
  }).trim()
}

function verifyInitialNativeRemote(root, commit, remoteRef) {
  const output = runInitialNativeCommand(root, 'git', ['ls-remote', '--exit-code', 'origin', remoteRef])
  if (output !== `${commit}\t${remoteRef}`) throw new Error('source commit is not the exact remote branch tip')
}

function assertInitialNativeELF(filename, arch) {
  const stat = fs.lstatSync(filename)
  if (!stat.isFile() || stat.nlink !== 1) throw new Error('ELF must be a regular file without links')
  const descriptor = fs.openSync(filename, 'r'), header = Buffer.alloc(64)
  try {
    if (fs.readSync(descriptor, header, 0, header.length, 0) !== header.length ||
        !header.subarray(0, 4).equals(Buffer.from('\x7fELF', 'binary')) ||
        header[4] !== 2 || header[5] !== 1 || header[6] !== 1 ||
        ![2, 3].includes(header.readUInt16LE(16)) || header.readUInt16LE(18) !== (arch === 'amd64' ? 62 : 183)) {
      throw new Error(`invalid Linux ELF64 ${arch}: ${path.basename(filename)}`)
    }
  } finally { fs.closeSync(descriptor) }
}

function normalizeInitialNativeFiles(directory, relative = '') {
  if (!fs.lstatSync(directory).isDirectory()) throw new Error('payload root must be a regular directory, not a link')
  for (const name of fs.readdirSync(directory).sort()) {
    const filename = path.join(directory, name), member = relative ? `${relative}/${name}` : name
    const stat = fs.lstatSync(filename)
    if (/[\r\n\\]/.test(member) || member.startsWith('-')) throw new Error('unsafe release member')
    if (stat.isDirectory()) normalizeInitialNativeFiles(filename, member)
    else {
      if (!stat.isFile() || stat.nlink !== 1) throw new Error('release must contain regular files without links')
      fs.chmodSync(filename, ['bin/control-api', 'bin/agent-gateway'].includes(member) ? 0o755 : 0o644)
      fs.utimesSync(filename, 0, 0)
    }
  }
}

export function buildInitialNativeRelease(options) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const { commit, remoteRef, previousSourceCommit, baseline, outputDir: requestedOutput, version, arch, siteKey, allowEmptySiteKey, keyID } = options
  if (!objectID.test(commit) || commit === predecessor || (baseline === true ? previousSourceCommit !== undefined : baseline !== undefined || previousSourceCommit !== predecessor) ||
      !/^refs\/heads\/[a-zA-Z0-9_./-]+$/.test(remoteRef ?? '') || !stableVersion.test(version) ||
      !['amd64', 'arm64'].includes(arch) || !path.isAbsolute(requestedOutput ?? '') ||
      (!siteKey && !allowEmptySiteKey) || keyID !== undefined && (typeof keyID !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(keyID))) throw new Error('invalid initial build arguments or unapproved release lineage')
  const outputDir = path.join(fs.realpathSync(path.dirname(requestedOutput)), path.basename(requestedOutput))
  if (fs.existsSync(outputDir) || fs.lstatSync(outputDir, { throwIfNoEntry: false })) {
    throw new Error('output directory already exists; refusing to overwrite')
  }
  verifyInitialNativeRemote(root, commit, remoteRef)
  if (runInitialNativeCommand(root, 'git', ['rev-parse', `${commit}^{commit}`]) !== commit ||
      !baseline && runInitialNativeCommand(root, 'git', ['rev-parse', `${predecessor}^{tree}`]) !== predecessorTree) {
    throw new Error('invalid source commit or approved release lineage tree')
  }
  if (!baseline) runInitialNativeCommand(root, 'git', ['merge-base', '--is-ancestor', predecessor, commit])
  const tree = runInitialNativeCommand(root, 'git', ['rev-parse', `${commit}^{tree}`])
  if (!objectID.test(tree)) throw new Error('invalid source tree')
  const migrations = runInitialNativeCommand(root, 'git', ['ls-tree', '--name-only', `${commit}:services/control-api/migrations`])
    .split('\n').filter((name) => migrationName.test(name)).sort()
  if (!migrations.length || migrations.some((name) => !migrations.includes(name.replace(/\.(up|down)\.sql$/,
    (_, direction) => `.${direction === 'up' ? 'down' : 'up'}.sql`)))) throw new Error('formal migrations must have up/down pairs')
  const builtAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-initial-package-')))
  try {
    const source = path.join(work, 'source'), release = path.join(work, 'release'), result = path.join(work, 'result')
    for (const directory of [source, result, path.join(release, 'bin'), path.join(release, 'migrations')]) {
      fs.mkdirSync(directory, { recursive: true })
    }
    runInitialNativeCommand(root, 'git', ['archive', '--format=tar', `--output=${path.join(work, 'source.tar')}`, commit])
    runInitialNativeCommand(work, 'tar', ['-xf', path.join(work, 'source.tar'), '-C', source])
    const buildEnv = { ...process.env, CGO_ENABLED: '0', GOOS: 'linux', GOARCH: arch, GOAMD64: 'v1', GOENV: 'off', GOWORK: path.join(source, 'go.work'),
      VITE_API_BASE_URL: '', VITE_RELEASE: commit, VITE_PACKAGE_COMMERCE_ENABLED: 'true', VITE_TURNSTILE_SITE_KEY: siteKey ?? '' }
    delete buildEnv.GOFLAGS; delete buildEnv.GOEXPERIMENT
    const flags = `-s -w -X main.controlVersion=${version} -X main.controlSourceCommit=${commit} -X main.controlSourceTree=${tree} -X main.controlBuildTime=${builtAt}`
    for (const [component, target, ldflags] of [
      ['control-api', './services/control-api/cmd/control-api', flags],
      ['agent-gateway', './services/agent-gateway/cmd/agent-gateway', '-s -w'],
      ['control-upgrade-runner', './services/control-api/cmd/control-upgrade-runner', '-s -w'],
    ]) {
      const filename = path.join(component === 'control-upgrade-runner' ? result : path.join(release, 'bin'), component)
      if (component === 'control-upgrade-runner') {
        runInitialNativeCommand(path.join(source, 'services/control-api'), 'go', ['build', '-trimpath', '-buildvcs=false', '-mod=readonly', `-ldflags=${ldflags}`, '-o', filename, './cmd/control-upgrade-runner'], { ...buildEnv, GOWORK: 'off' })
      } else runInitialNativeCommand(source, 'go', ['build', '-trimpath', '-buildvcs=false', `-ldflags=${ldflags}`, '-o', filename, target], buildEnv)
      assertInitialNativeELF(filename, arch)
      fs.chmodSync(filename, 0o755); fs.utimesSync(filename, 0, 0)
    }
    runInitialNativeCommand(source, 'pnpm', ['install', '--frozen-lockfile', '--filter', '@cdnca/web...'], buildEnv)
    runInitialNativeCommand(source, 'pnpm', ['--filter', '@cdnca/web', 'build'], buildEnv)
    const web = path.join(source, 'apps/web/dist')
    normalizeInitialNativeFiles(web)
    const runtimeScript = /<script\b[^>]*\ssrc\s*=\s*["'](?:\/dashboard)?\/runtime-config\.js["'][^>]*>/i
    if (!runtimeScript.test(fs.readFileSync(path.join(web, 'index.html'), 'utf8').replace(/<!--[\s\S]*?-->/g, '')) ||
        !fs.existsSync(path.join(web, 'runtime-config.js'))) throw new Error('Web must include the external runtime-config hook and default file')
    // Community edition: no public website (static/web/site); nginx then serves the console entry at /.
    fs.cpSync(web, path.join(release, 'static/web'), { recursive: true, dereference: false })
    // The console serves /downloads/install-node.sh from the active release, so
    // a management upgrade also refreshes the node installer it hands out.
    const nodeInstaller = path.join(source, 'scripts/install-node.sh')
    if (!fs.lstatSync(nodeInstaller).isFile() || !fs.readFileSync(nodeInstaller, 'utf8').startsWith('#!/usr/bin/env bash\n')) {
      throw new Error('release must include the node installer')
    }
    fs.mkdirSync(path.join(release, 'static/web/downloads'), { recursive: true })
    fs.copyFileSync(nodeInstaller, path.join(release, 'static/web/downloads/install-node.sh'), fs.constants.COPYFILE_EXCL)
    // Billing integration PHP modules (ADR 0019): integrations/build.sh output, served at
    // /downloads/billing-bridge/ from the active release so an upgrade refreshes them.
    // A source tree without integrations/build.sh (older commits, test fixtures) ships none.
    if (fs.lstatSync(path.join(source, 'integrations/build.sh'), { throwIfNoEntry: false })?.isFile()) {
      runInitialNativeCommand(path.join(source, 'integrations'), 'bash', ['build.sh'], buildEnv)
      fs.mkdirSync(path.join(release, 'static/web/downloads/billing-bridge'), { recursive: true })
      for (const name of ['cdnca-whmcs.zip', 'cdnca-zjmf.zip', 'cdnca-zjmf-v10.zip']) {
        fs.copyFileSync(path.join(source, 'integrations/dist', name), path.join(release, 'static/web/downloads/billing-bridge', name), fs.constants.COPYFILE_EXCL)
      }
    }
    const migrationDirectory = path.join(source, 'services/control-api/migrations')
    if (!fs.lstatSync(migrationDirectory).isDirectory() ||
        JSON.stringify(fs.readdirSync(migrationDirectory).filter((name) => migrationName.test(name)).sort()) !== JSON.stringify(migrations)) {
      throw new Error('archive must include the complete formal migration set')
    }
    for (const name of migrations) {
      const filename = path.join(migrationDirectory, name), stat = fs.lstatSync(filename)
      if (!stat.isFile() || stat.nlink !== 1) throw new Error('migration must be a regular file without links')
      fs.copyFileSync(filename, path.join(release, 'migrations', name), fs.constants.COPYFILE_EXCL)
    }
    copyNativeClickHouse(source, release)
    copyNativeRecoveryRunbook(source, release)
    normalizeInitialNativeFiles(release)
    const manifest = createNativeManifest(release, { version, built_at: builtAt, key_id: keyID,
      source: baseline ? { commit, tree } : { commit, tree, previous_commit: predecessor }, platform: { os: 'linux', arch } })
    const encoded = JSON.stringify(manifest, null, 2) + '\n'
    fs.writeFileSync(path.join(release, 'release.manifest.json'), encoded, { flag: 'wx', mode: 0o644 })
    fs.chmodSync(path.join(release, 'release.manifest.json'), 0o644)
    fs.utimesSync(path.join(release, 'release.manifest.json'), 0, 0)
    fs.writeFileSync(path.join(work, 'members'), ['release.manifest.json', ...manifest.files.map((file) => file.path)].join('\n') + '\n', { flag: 'wx' })
    const ownership = runInitialNativeCommand(work, 'tar', ['--version']).includes('bsdtar')
      ? ['--uid', '0', '--gid', '0', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    const archiveName = keyID ? 'native-management.unsigned.tar' : 'native-management.tar', archive = path.join(result, archiveName)
    runInitialNativeCommand(release, 'tar', ['--format=ustar', ...ownership, '-cf', archive, '-T', path.join(work, 'members')])
    const runner = fs.readFileSync(path.join(result, 'control-upgrade-runner'))
    const artifact = { schema: `cdnca.native-management.unsigned-build/v${keyID ? 2 : 1}`, installation_mode: 'first-native-baseline',
      previous_source_semantics: baseline ? initialBaselineSemantics : 'release-lineage-not-host-deployment', source: manifest.source, version, built_at: builtAt,
      file: archiveName, sha256: sha256(fs.readFileSync(archive)), bytes: fs.statSync(archive).size, signing_required: true,
      runner: { file: 'control-upgrade-runner', sha256: sha256(runner), bytes: runner.length, source: { commit, tree },
        platform: { os: 'linux', arch }, version, signing_required: true },
      // The license service stores this on registration; a baseline has nothing to roll back to.
      ...(baseline ? { schema_gate: nativeSchemaGateFacts(manifest) } : {}) }
    verifyInitialNativeRemote(root, commit, remoteRef)
    fs.mkdirSync(outputDir, { mode: 0o700 })
    for (const name of [archiveName, 'control-upgrade-runner']) {
      fs.copyFileSync(path.join(result, name), path.join(outputDir, name), fs.constants.COPYFILE_EXCL)
    }
    fs.writeFileSync(path.join(outputDir, 'release.manifest.json'), encoded, { flag: 'wx', mode: 0o644 })
    if (keyID) {
      fs.cpSync(release, path.join(outputDir, 'payload'), { recursive: true, dereference: false, errorOnExist: true })
      fs.writeFileSync(path.join(outputDir, 'release.signing-data'), manifest.schema + '\n' + encoded, { flag: 'wx', mode: 0o600 })
    }
    // A partial I/O failure cannot leave a successful build record.
    fs.writeFileSync(path.join(outputDir, 'build.json'), JSON.stringify(artifact, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
    return artifact
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const keys = { '--source-commit': 'commit', '--remote-ref': 'remoteRef', '--previous-source-commit': 'previousSourceCommit',
      '--output-dir': 'outputDir', '--version': 'version', '--arch': 'arch', '--turnstile-site-key': 'siteKey', '--key-id': 'keyID' }
    const options = {}
    for (let index = 2; index < process.argv.length; index++) {
      const flag = process.argv[index]
      if (flag === '--allow-empty-turnstile-site-key' && !options.allowEmptySiteKey) { options.allowEmptySiteKey = true; continue }
      if (flag === '--baseline' && !options.baseline) { options.baseline = true; continue }
      const key = keys[flag], value = process.argv[++index]
      if (!key || value === undefined || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
      options[key] = value
    }
    console.log(JSON.stringify(buildInitialNativeRelease(options), null, 2))
  } catch (error) {
    console.error(`initial native release build: ${error.message}`)
    process.exitCode = 1
  }
}
