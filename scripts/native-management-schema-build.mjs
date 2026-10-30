#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { createNativeManifest, preserveNativeWebFiles, verifyNativeManifestSignature } from './native-release-package.mjs'
import { nativeControlInstallCommand, nativeControlInstallFile } from './native-control-install-package.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const schema = 'cdnca.native-management.release/v2', smallLimit = 8 << 20, archiveLimit = 285229182
const initialPredecessor = '8b26d83421351b96a715fefa1d7f4fcdbb94ed1a'
const encode = (value) => JSON.stringify(value, null, 2) + '\n'
const hash = (value) => createHash('sha256').update(value).digest('hex')
const transitions = {
  '1.0.12': { previous: '1.0.11', from: 269, to: 270, stems: ['270_l2_topology_default_region'] },
  '1.0.13': { previous: '1.0.12', from: 270, to: 271, stems: ['271_node_network_inventory'] },
  '1.0.16': { previous: '1.0.15', from: 271, to: 273, stems: ['272_site_group_administration', '273_validator_search_path'] },
  '1.0.22': { previous: '1.0.17', previousCommit: 'd937236fba23ecf63319862c68e78b50158824e4', from: 273, to: 275,
    stems: ['274_node_line_endpoint_sort_order', '275_node_line_endpoint_display_ids'] },
  '1.0.23': { previous: '1.0.22', previousCommit: '2166adcd3719d10e69ce427c2ca6af59d572792f', firstBaseline: true, from: 275, to: 277,
    stems: ['276_certificate_asset_owner', '277_node_session_capabilities'], sql: {
      '276_certificate_asset_owner.up.sql': '300294799eb72125955b03c7fbabb35f67c6913aa776bb4a134ab4545c33c1df',
      '276_certificate_asset_owner.down.sql': '3151ec744c3457f8d65c5b76fc3713b6d0b4f3243a7f848831bec872269c39eb',
      '277_node_session_capabilities.up.sql': '32fd892953ecdda2a5119ae57287ab03765c78d3b3a551f241b9ddccd295a6ff',
      '277_node_session_capabilities.down.sql': 'ad2055218fe73ca6506ae75273d6aec1d92c57e38f1787fe7b5adb0832d33693',
    } },
}

function schemaBuildDirectory(directory) {
  if (!path.isAbsolute(directory ?? '') || path.resolve(directory) !== directory ||
      fs.realpathSync(directory) !== directory || !fs.lstatSync(directory).isDirectory()) throw new Error('input directory must be canonical without links')
  return directory
}

function schemaBuildJSON(filename, snapshots) {
  const fact = nativeControlInstallFile(filename, smallLimit), raw = fs.readFileSync(filename)
  const value = JSON.parse(raw)
  if (hash(raw) !== fact.sha256 || encode(value) !== raw.toString('utf8')) throw new Error('noncanonical or changing input JSON')
  snapshots.push({ filename, limit: smallLimit, fact })
  return { value, raw }
}

// Unsigned v2 cannot pass the signed Go validator yet. Accept only the regular
// USTAR subset emitted by our builders; never ask tar to extract untrusted paths.
function schemaBuildTar(filename, manifest, raw, signature, destination) {
  const fact = nativeControlInstallFile(filename, archiveLimit), archive = fs.readFileSync(filename)
  if (hash(archive) !== fact.sha256 || archive.length !== fact.bytes || archive.length % 512 !== 0) throw new Error('archive changed or is not plain USTAR')
  const entries = [...manifest.files, { path: 'release.manifest.json', bytes: raw.length, sha256: hash(raw), mode: 0o644 },
    ...(signature ? [{ path: 'release.manifest.sig', bytes: signature.length, sha256: hash(signature), mode: 0o644 }] : [])]
  const expected = new Map(entries.map((file) => [file.path, file])), seen = new Set()
  if (expected.size !== entries.length || entries.length > 65537) throw new Error('duplicate or excessive archive inventory')
  if (destination) fs.mkdirSync(destination, { mode: 0o700 })
  let offset = 0
  while (offset + 512 <= archive.length && archive.subarray(offset, offset + 512).some((byte) => byte !== 0)) {
    const header = archive.subarray(offset, offset + 512)
    const text = (start, size) => {
      const field = header.subarray(start, start + size), end = field.indexOf(0)
      if (end >= 0 && field.subarray(end).some((byte) => byte !== 0)) throw new Error('invalid USTAR text field')
      return new TextDecoder('utf-8', { fatal: true }).decode(end < 0 ? field : field.subarray(0, end))
    }
    const octal = (start, size) => {
      const value = header.subarray(start, start + size).toString('latin1')
      if (!/^ *[0-7]+[\0 ]*$/.test(value)) throw new Error('invalid USTAR number')
      const parsed = Number.parseInt(value.trim(), 8)
      if (!Number.isSafeInteger(parsed)) throw new Error('unsafe USTAR number')
      return parsed
    }
    const prefix = text(345, 155), name = (prefix ? prefix + '/' : '') + text(0, 100)
    const checksum = [...header].reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0)
    const bytes = octal(124, 12), mode = octal(100, 8), end = offset + 512 + bytes, next = offset + 512 + Math.ceil(bytes / 512) * 512
    octal(136, 12)
    if (text(257, 6) !== 'ustar' || text(263, 2) !== '00' || text(156, 1) !== '0' || text(157, 100) !== '' ||
        octal(148, 8) !== checksum || octal(108, 8) !== 0 || octal(116, 8) !== 0 || next > archive.length ||
        name === '' || name === '.' || name === '..' || name.startsWith('/') || name.startsWith('../') || name.startsWith('-') ||
        path.posix.normalize(name) !== name || /[\0\r\n\\]/.test(name) || name.length > 1024 || seen.has(name)) throw new Error('unsafe USTAR member')
    const body = archive.subarray(offset + 512, end), file = expected.get(name)
    if (!file || file.bytes !== bytes || file.mode !== mode || ![0o644, 0o755].includes(mode) || file.sha256 !== hash(body) ||
        archive.subarray(end, next).some((byte) => byte !== 0)) throw new Error('archive file inventory differs from manifest')
    seen.add(name)
    if (destination) {
      const target = path.join(destination, name)
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 })
      fs.writeFileSync(target, body, { flag: 'wx', mode }); fs.chmodSync(target, mode)
    }
    offset = next
  }
  if (seen.size !== expected.size || archive.length - offset < 1024 || archive.subarray(offset).some((byte) => byte !== 0)) throw new Error('incomplete archive or nonzero trailing data')
  if (!isDeepStrictEqual(nativeControlInstallFile(filename, archiveLimit), fact)) throw new Error('archive changed during validation')
  return fact
}

function schemaBuildELF(filename, arch) {
  nativeControlInstallFile(filename, archiveLimit)
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW), header = Buffer.alloc(64)
  try {
    if (fs.readSync(descriptor, header, 0, 64, 0) !== 64 || !header.subarray(0, 7).equals(Buffer.from('\x7fELF\x02\x01\x01', 'binary')) ||
        ![2, 3].includes(header.readUInt16LE(16)) || header.readUInt16LE(18) !== (arch === 'amd64' ? 62 : 183)) throw new Error('invalid native ELF platform')
  } finally { fs.closeSync(descriptor) }
}

// cp/copyFile may apply the caller's umask. Restore only verified bytes inside
// our new copy, never an input tree or a link introduced during copying.
function schemaBuildModes(directory, files) {
  for (const file of files) {
    const filename = path.join(directory, file.path), stat = fs.lstatSync(filename)
    if (fs.realpathSync(filename) !== filename || !stat.isFile() || stat.nlink !== 1 || stat.size !== file.bytes ||
        hash(fs.readFileSync(filename)) !== file.sha256) throw new Error('copied file differs from verified inventory or contains a link')
    fs.chmodSync(filename, file.mode)
  }
}

function schemaBuildSource(commit, remoteRef) {
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_'))),
    GIT_GRAFT_FILE: '/dev/null', GIT_CONFIG_COUNT: '0' }
  const git = (...args) => nativeControlInstallCommand(repository, 'git', args, env)
  const check = () => {
    if (git('ls-remote', '--exit-code', 'origin', remoteRef) !== `${commit}\t${remoteRef}`) throw new Error('source is not the exact pushed remote tip')
  }
  check()
  if (git('rev-parse', '--is-shallow-repository') !== 'false' || git('rev-parse', `${commit}^{commit}`) !== commit) throw new Error('incomplete source repository')
  return { git, check }
}

function schemaBuildRunner(directory, build, manifest, snapshots) {
  const filename = path.join(directory, 'control-upgrade-runner'), fact = nativeControlInstallFile(filename, archiveLimit)
  if (!isDeepStrictEqual(build.runner, { file: 'control-upgrade-runner', sha256: fact.sha256, bytes: fact.bytes,
    source: { commit: manifest.source.commit, tree: manifest.source.tree }, platform: manifest.platform,
    version: manifest.version, signing_required: true }) || fact.mode !== 0o755) throw new Error('runner provenance mismatch')
  schemaBuildELF(filename, manifest.platform.arch)
  snapshots.push({ filename, limit: archiveLimit, fact })
}

function verifySchemaUpgradeInputs(options, work) {
  const snapshots = [], { initialBuildDir, baselineBuildDir, artifactPublicKeyPath, commit, remoteRef } = options
  const read = (directory, name) => schemaBuildJSON(path.join(directory, name), snapshots)
  const initial = read(initialBuildDir, 'release.manifest.json'), previous = read(baselineBuildDir, 'release.manifest.json')
  const build = read(initialBuildDir, 'build.json').value, baseline = read(baselineBuildDir, 'build.json').value
  const transition = transitions[initial.value.version]
  const firstBaseline = transition?.firstBaseline === true
  if (!transition || previous.value.version !== transition.previous || previous.value.schema !== schema || initial.value.schema !== schema ||
      (transition.previousCommit && previous.value.source?.commit !== transition.previousCommit) ||
      initial.value.key_id !== previous.value.key_id || !isDeepStrictEqual(initial.value.platform, previous.value.platform) ||
      initial.value.source?.commit !== commit || previous.value.source?.commit === commit ||
      (firstBaseline ? previous.value.source?.previous_commit !== initialPredecessor : previous.value.source?.previous_commit === initialPredecessor) ||
      [initial.value, previous.value].some((manifest) => !['commit', 'tree', 'previous_commit'].every((key) => /^[a-f0-9]{40}$/.test(manifest.source?.[key] ?? '')))) throw new Error('unsupported schema transition or source identity')
  if (transition.sql && (!isDeepStrictEqual(Object.keys(transition.sql).sort(), transition.stems.flatMap((stem) => ['up', 'down'].map((direction) => `${stem}.${direction}.sql`)).sort()) ||
      Object.values(transition.sql).some((digest) => typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)))) throw new Error('unreviewed schema migration pins; build disabled')
  const signedName = 'native-management.tar', unsignedName = 'native-management.unsigned.tar'
  const expected = (manifest, signed) => ({ schema: `cdnca.native-management.${signed ? 'signed' : 'unsigned'}-build/v2`,
    ...(!signed || firstBaseline ? { installation_mode: 'first-native-baseline', previous_source_semantics: 'release-lineage-not-host-deployment' } : {}),
    source: manifest.source, version: manifest.version, built_at: manifest.built_at, file: signed ? signedName : unsignedName,
    sha256: signed ? baseline.sha256 : build.sha256, bytes: signed ? baseline.bytes : build.bytes, signing_required: !signed,
    ...(!signed || firstBaseline ? { runner: signed ? baseline.runner : build.runner } : {}) })
  if (!isDeepStrictEqual(baseline, expected(previous.value, true)) || !isDeepStrictEqual(build, expected(initial.value, false))) throw new Error('build provenance mismatch; an initial package is not an upgrade baseline')
  const initialNames = ['build.json', 'control-upgrade-runner', unsignedName, 'payload', 'release.manifest.json', 'release.signing-data'].sort()
  if (!isDeepStrictEqual(fs.readdirSync(initialBuildDir).sort(), initialNames) ||
      !isDeepStrictEqual(fs.readdirSync(baselineBuildDir).sort(), ['build.json', signedName, 'release.manifest.json', 'release.manifest.sig',
        ...(firstBaseline ? ['control-upgrade-runner'] : [])].sort())) throw new Error('unexpected build directory inventory')
  for (const [filename, limit] of [[artifactPublicKeyPath, smallLimit], [path.join(baselineBuildDir, 'release.manifest.sig'), 128],
    [path.join(initialBuildDir, 'release.signing-data'), smallLimit + 128]]) {
    snapshots.push({ filename, limit, fact: nativeControlInstallFile(filename, limit) })
  }
  const signature = fs.readFileSync(path.join(baselineBuildDir, 'release.manifest.sig'))
  verifyNativeManifestSignature(previous.raw, signature.toString('utf8'), fs.readFileSync(artifactPublicKeyPath))
  if (!fs.readFileSync(path.join(initialBuildDir, 'release.signing-data')).equals(Buffer.concat([Buffer.from(schema + '\n'), initial.raw]))) throw new Error('initial signing data differs from manifest')
  schemaBuildRunner(initialBuildDir, build, initial.value, snapshots)
  if (firstBaseline) schemaBuildRunner(baselineBuildDir, baseline, previous.value, snapshots)
  const origin = schemaBuildSource(commit, remoteRef)
  const inputs = [{ ...previous, directory: baselineBuildDir, build: baseline, signed: true, payload: path.join(work, 'baseline') },
    { ...initial, directory: initialBuildDir, build, signed: false, payload: path.join(work, 'initial') }]
  for (const input of inputs) {
    const { value: manifest, raw, payload } = input
    if (origin.git('rev-parse', `${manifest.source.commit}^{tree}`) !== manifest.source.tree || manifest.source.commit === manifest.source.previous_commit) throw new Error('Git source tree mismatch')
    origin.git('merge-base', '--is-ancestor', manifest.source.previous_commit, manifest.source.commit)
    const filename = path.join(input.directory, input.build.file)
    const fact = schemaBuildTar(filename, manifest, raw, input.signed ? signature : null, payload)
    if (fact.sha256 !== input.build.sha256 || fact.bytes !== input.build.bytes) throw new Error('original archive digest differs from build.json')
    snapshots.push({ filename, limit: archiveLimit, fact })
    if (encode(createNativeManifest(payload, manifest)) !== raw.toString('utf8')) throw new Error('original manifest differs from full file inventory')
    if (manifest.files.some((file) => file.path.split('/').some((part) => ['.git', 'source.bundle'].includes(part)))) throw new Error('source-free release cannot contain private Git source')
    for (const name of ['bin/control-api', 'bin/agent-gateway']) schemaBuildELF(path.join(payload, name), manifest.platform.arch)
    const head = input.signed ? transition.from : transition.to, migrations = manifest.files.filter((file) => file.path.startsWith('migrations/'))
    const names = migrations.map((file) => file.path.slice('migrations/'.length))
    const entries = origin.git('ls-tree', `${manifest.source.commit}:services/control-api/migrations`).split('\n')
      .map((entry) => /^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(entry)).filter((entry) => entry && /^\d{3}_[a-z0-9_]+\.(up|down)\.sql$/.test(entry[4]))
    if (names.length !== head * 2 || !isDeepStrictEqual([...names].sort(), entries.map((entry) => entry[4]).sort()) ||
        Array.from({ length: head }, (_, index) => index + 1).some((number) => names.filter((name) => name.startsWith(String(number).padStart(3, '0') + '_')).length !== 2) ||
        names.some((name) => !names.includes(name.replace(/\.(up|down)\.sql$/, (_, direction) => `.${direction === 'up' ? 'down' : 'up'}.sql`)))) throw new Error('incomplete or unexpected migration inventory')
    for (const [, mode, type, blob, name] of entries) {
      const bytes = fs.readFileSync(path.join(payload, 'migrations', name))
      if (mode !== '100644' || type !== 'blob' || migrations.find((file) => file.path === 'migrations/' + name)?.mode !== 0o644 ||
          createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') !== blob) throw new Error('migration differs from exact Git source bytes or mode')
      if (!input.signed && transition.sql?.[name] && hash(bytes) !== transition.sql[name]) throw new Error('migration differs from fixed reviewed SQL pin')
    }
  }
  origin.git('merge-base', '--is-ancestor', previous.value.source.commit, commit)
  const migrationFiles = (manifest) => manifest.files.filter((file) => file.path.startsWith('migrations/'))
  const additions = transition.stems.flatMap((stem) => ['down', 'up'].map((direction) => `migrations/${stem}.${direction}.sql`))
  if (!isDeepStrictEqual(migrationFiles(previous.value), migrationFiles(initial.value).filter((file) => !additions.includes(file.path))) ||
      !additions.every((name) => initial.value.files.some((file) => file.path === name))) throw new Error('old migration changed or unexpected SQL addition')
  if (initial.value.files.some((file) => !['bin/control-api', 'bin/agent-gateway'].includes(file.path) && !file.path.startsWith('static/web/') && !file.path.startsWith('migrations/'))) throw new Error('initial payload contains unowned files')
  const check = () => {
    for (const { filename, limit, fact } of snapshots) if (!isDeepStrictEqual(nativeControlInstallFile(filename, limit), fact)) throw new Error('input changed during schema build')
    const payload = schemaBuildDirectory(path.join(initialBuildDir, 'payload'))
    if (fs.lstatSync(path.join(payload, 'release.manifest.sig'), { throwIfNoEntry: false }) ||
        encode(createNativeManifest(payload, initial.value)) !== initial.raw.toString('utf8') ||
        !fs.readFileSync(path.join(payload, 'release.manifest.json')).equals(initial.raw)) throw new Error('initial payload differs from original manifest')
  }
  check()
  return { initial: inputs[1], previous: inputs[0], additions, origin, check }
}

export function buildNativeSchemaUpgrade(options) {
  const { commit, remoteRef, initialBuildDir, baselineBuildDir, artifactPublicKeyPath, outputDir } = options
  if (!/^[a-f0-9]{40}$/.test(commit ?? '') || !/^refs\/heads\/[A-Za-z0-9_./-]+$/.test(remoteRef ?? '') ||
      ![initialBuildDir, baselineBuildDir, artifactPublicKeyPath, outputDir].every((name) => path.isAbsolute(name ?? ''))) throw new Error('invalid schema build arguments')
  schemaBuildDirectory(initialBuildDir); schemaBuildDirectory(baselineBuildDir)
  const parent = schemaBuildDirectory(path.dirname(outputDir))
  if (path.resolve(outputDir) !== outputDir || fs.lstatSync(outputDir, { throwIfNoEntry: false }) ||
      [initialBuildDir, baselineBuildDir].some((directory) => outputDir.startsWith(directory + path.sep)) || parent === outputDir) throw new Error('output must be a new canonical directory outside immutable inputs')
  nativeControlInstallFile(artifactPublicKeyPath, smallLimit)
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-schema-build-')))
  try {
    const inputs = verifySchemaUpgradeInputs(options, work), { previous, initial, additions, origin } = inputs
    const release = path.join(work, 'release')
    fs.cpSync(previous.payload, release, { recursive: true, dereference: false, errorOnExist: true })
    schemaBuildDirectory(release)
    schemaBuildModes(release, [...previous.value.files, ...['release.manifest.json', 'release.manifest.sig'].map((name) =>
      ({ path: name, ...nativeControlInstallFile(path.join(previous.payload, name), smallLimit) }))])
    if (encode(createNativeManifest(release, previous.value)) !== previous.raw.toString('utf8')) throw new Error('copied baseline changed')
    fs.unlinkSync(path.join(release, 'release.manifest.json')); fs.unlinkSync(path.join(release, 'release.manifest.sig'))
    for (const name of ['bin/control-api', 'bin/agent-gateway']) fs.copyFileSync(path.join(initial.payload, name), path.join(release, name))
    fs.cpSync(path.join(initial.payload, 'static/web'), path.join(release, 'static/web'), { recursive: true, dereference: false })
    for (const name of additions) fs.copyFileSync(path.join(initial.payload, name), path.join(release, name), fs.constants.COPYFILE_EXCL)
    schemaBuildModes(release, initial.value.files.filter((file) => !file.path.startsWith('migrations/') || additions.includes(file.path)))
    preserveNativeWebFiles(previous.payload, release, previous.value.files)
    schemaBuildModes(release, previous.value.files.filter((file) => file.path === 'static/web/runtime-config.js'))
    const metadata = { ...initial.value, source: { ...initial.value.source, previous_commit: previous.value.source.commit } }
    const manifest = createNativeManifest(release, metadata), raw = Buffer.from(encode(manifest))
    for (const old of previous.value.files) {
      const current = manifest.files.find((file) => file.path === old.path)
      if (!current || (!['bin/control-api', 'bin/agent-gateway'].includes(old.path) &&
          (!old.path.startsWith('static/web/') || old.path.startsWith('static/web/assets/') || old.path === 'static/web/runtime-config.js') &&
          !isDeepStrictEqual(current, old))) throw new Error('cloned release lost or changed a preserved baseline file')
    }
    fs.writeFileSync(path.join(release, 'release.manifest.json'), raw, { flag: 'wx', mode: 0o644 })
    fs.chmodSync(path.join(release, 'release.manifest.json'), 0o644)
    const names = ['release.manifest.json', ...manifest.files.map((file) => file.path)]
    for (const name of names) fs.utimesSync(path.join(release, name), 0, 0)
    fs.writeFileSync(path.join(work, 'members'), names.join('\n') + '\n', { flag: 'wx', mode: 0o600 })
    const archive = path.join(work, 'native-management.unsigned.tar')
    const ownership = nativeControlInstallCommand(work, 'tar', ['--version']).includes('bsdtar')
      ? ['--uid', '0', '--gid', '0', '--uname', '', '--gname', '', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    nativeControlInstallCommand(release, 'tar', ['--format=ustar', ...ownership, '-cf', archive, '-T', path.join(work, 'members')], { ...process.env, COPYFILE_DISABLE: '1' })
    const artifact = schemaBuildTar(archive, manifest, raw, null)
    inputs.check(); origin.check()
    const result = { schema: 'cdnca.native-management.unsigned-build/v2', source: manifest.source, version: manifest.version,
      built_at: manifest.built_at, file: path.basename(archive), sha256: artifact.sha256, bytes: artifact.bytes, signing_required: true }
    fs.mkdirSync(outputDir, { mode: 0o700 })
    fs.copyFileSync(archive, path.join(outputDir, result.file), fs.constants.COPYFILE_EXCL); fs.chmodSync(path.join(outputDir, result.file), 0o600)
    fs.cpSync(release, path.join(outputDir, 'payload'), { recursive: true, dereference: false, errorOnExist: true })
    schemaBuildDirectory(path.join(outputDir, 'payload'))
    schemaBuildModes(path.join(outputDir, 'payload'), [...manifest.files, { path: 'release.manifest.json', bytes: raw.length, sha256: hash(raw), mode: 0o644 }])
    if (encode(createNativeManifest(path.join(outputDir, 'payload'), manifest)) !== raw.toString('utf8') ||
        !fs.readFileSync(path.join(outputDir, 'payload/release.manifest.json')).equals(raw) ||
        fs.lstatSync(path.join(outputDir, 'payload/release.manifest.sig'), { throwIfNoEntry: false }) ||
        !isDeepStrictEqual(nativeControlInstallFile(path.join(outputDir, result.file), archiveLimit), { ...artifact, mode: 0o600 })) throw new Error('output changed while copying')
    fs.writeFileSync(path.join(outputDir, 'release.manifest.json'), raw, { flag: 'wx', mode: 0o644 })
    fs.chmodSync(path.join(outputDir, 'release.manifest.json'), 0o644)
    fs.writeFileSync(path.join(outputDir, 'release.signing-data'), Buffer.concat([Buffer.from(schema + '\n'), raw]), { flag: 'wx', mode: 0o600 })
    // No first-install lineage, runner, signing claim or successful record on I/O failure.
    fs.writeFileSync(path.join(outputDir, 'build.json'), encode(result), { flag: 'wx', mode: 0o600 })
    return result
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

function schemaBuildCLI(args) {
  const keys = { '--source-commit': 'commit', '--remote-ref': 'remoteRef', '--initial-build-dir': 'initialBuildDir',
    '--baseline-build-dir': 'baselineBuildDir', '--artifact-public-key': 'artifactPublicKeyPath', '--output-dir': 'outputDir' }, options = {}
  for (let index = 0; index < args.length; index += 2) {
    const key = keys[args[index]], value = args[index + 1]
    if (!key || !value || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
    options[key] = value
  }
  return buildNativeSchemaUpgrade(options)
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(encode(schemaBuildCLI(process.argv.slice(2)))) }
  catch (error) { console.error(`native schema build: ${error.message}`); process.exitCode = 1 }
}
