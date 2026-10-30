#!/usr/bin/env node
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { createNativeManifest, initialBaselineSemantics, nativeSchemaGateFacts, verifyNativeManifestSignature } from './native-release-package.mjs'
import { nativeControlInstallCommand, nativeControlInstallFile, nativeControlInstallSource,
  verifyNativeControlInstallBundle, verifyNativeReleaseMigrations, validateNativeReleaseWithGo, buildNativeUpgradeRunner } from './native-control-install-package.mjs'

const encode = (value) => JSON.stringify(value, null, 2) + '\n'
const smallLimit = 8 << 20, binaryLimit = 285229182

// Signing keys stay outside the build machine. This command accepts only a
// detached signature and an independently configured public key.
export function finalizeNativeReleaseSignature({ buildDir, remoteRef, signaturePath, publicKeyPath, outputDir }) {
  if (![buildDir, signaturePath, publicKeyPath, outputDir].every((name) => path.isAbsolute(name ?? '')) ||
      !fs.lstatSync(buildDir).isDirectory() || fs.realpathSync(buildDir) !== buildDir) throw new Error('invalid signing paths')
  const output = path.join(fs.realpathSync(path.dirname(outputDir)), path.basename(outputDir))
  if (fs.lstatSync(output, { throwIfNoEntry: false })) throw new Error('output exists; refusing to overwrite')
  for (const [name, limit] of [['build.json', smallLimit], ['release.manifest.json', smallLimit], ['native-management.unsigned.tar', binaryLimit]]) {
    nativeControlInstallFile(path.join(buildDir, name), limit)
  }
  nativeControlInstallFile(fs.realpathSync(signaturePath), 128)
  nativeControlInstallFile(fs.realpathSync(publicKeyPath), smallLimit)
  const raw = fs.readFileSync(path.join(buildDir, 'release.manifest.json')), signature = fs.readFileSync(signaturePath, 'utf8')
  const manifest = verifyNativeManifestSignature(raw, signature, fs.readFileSync(publicKeyPath)), build = JSON.parse(fs.readFileSync(path.join(buildDir, 'build.json')))
  const payload = path.join(buildDir, 'payload')
  if (!fs.lstatSync(payload).isDirectory() || fs.realpathSync(payload) !== payload ||
      encode(createNativeManifest(payload, manifest)) !== raw.toString('utf8') ||
      !fs.readFileSync(path.join(payload, 'release.manifest.json')).equals(raw) ||
      fs.lstatSync(path.join(payload, 'release.manifest.sig'), { throwIfNoEntry: false })) throw new Error('unsigned payload differs from signed manifest')
  const unsigned = nativeControlInstallFile(path.join(buildDir, 'native-management.unsigned.tar'), binaryLimit)
  if (build.schema !== 'cdnca.native-management.unsigned-build/v2' || build.file !== 'native-management.unsigned.tar' || build.signing_required !== true ||
      build.sha256 !== unsigned.sha256 || build.bytes !== unsigned.bytes || build.version !== manifest.version || build.built_at !== manifest.built_at ||
      !isDeepStrictEqual(build.source, manifest.source)) throw new Error('unsigned build provenance mismatch')
  if (build.installation_mode !== undefined && (build.installation_mode !== 'first-native-baseline' || !build.runner ||
      build.previous_source_semantics !== (manifest.source.previous_commit === undefined ? initialBaselineSemantics : 'release-lineage-not-host-deployment'))) {
    throw new Error('invalid first-install lineage')
  }
  if (manifest.source.previous_commit === undefined && (build.installation_mode === undefined || build.schema_gate?.rollback_min_version !== undefined)) {
    throw new Error('a release without predecessor must be a first-install baseline without rollback target')
  }
  // Schema gate facts (native-release-package.mjs) go to the license service on registration and are
  // immutable there: carry them into the signed build.json only if they still match the signed manifest.
  if (build.schema_gate !== undefined && !isDeepStrictEqual(build.schema_gate, nativeSchemaGateFacts(manifest, build.schema_gate?.rollback_min_version))) {
    throw new Error('schema gate facts do not match the signed manifest')
  }
  const origin = nativeControlInstallSource(manifest.source.commit, remoteRef)
  if (origin.tree !== manifest.source.tree || manifest.source.commit === manifest.source.previous_commit) throw new Error('source tree or lineage mismatch')
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-signature-')))
  try {
    const bundle = path.join(work, 'source.bundle')
    origin.git('bundle', 'create', bundle, 'HEAD'); fs.chmodSync(bundle, 0o600)
    const source = verifyNativeControlInstallBundle(bundle, manifest, work)
    verifyNativeReleaseMigrations(manifest, source)
    const staging = path.join(work, 'payload')
    fs.cpSync(payload, staging, { recursive: true, dereference: false, errorOnExist: true })
    if (!fs.lstatSync(staging).isDirectory() || encode(createNativeManifest(staging, manifest)) !== raw.toString('utf8') ||
        !fs.readFileSync(path.join(staging, 'release.manifest.json')).equals(raw)) throw new Error('payload changed during signing')
    fs.writeFileSync(path.join(staging, 'release.manifest.sig'), signature.replace(/\n$/, '') + '\n', { flag: 'wx', mode: 0o644 })
    const names = ['release.manifest.json', 'release.manifest.sig', ...manifest.files.map((file) => file.path)]
    for (const name of names) {
      fs.chmodSync(path.join(staging, name), manifest.files.find((file) => file.path === name)?.mode ?? 0o644)
      fs.utimesSync(path.join(staging, name), 0, 0)
    }
    fs.writeFileSync(path.join(work, 'members'), names.join('\n') + '\n', { flag: 'wx', mode: 0o600 })
    const ownership = nativeControlInstallCommand(work, 'tar', ['--version']).includes('bsdtar')
      ? ['--uid', '0', '--gid', '0', '--uname', '', '--gname', '', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    const archive = path.join(work, 'native-management.tar')
    nativeControlInstallCommand(staging, 'tar', ['--format=ustar', ...ownership, '-cf', archive, '-T', path.join(work, 'members')], { ...process.env, COPYFILE_DISABLE: '1' })
    const artifact = nativeControlInstallFile(archive, binaryLimit)
    validateNativeReleaseWithGo(archive, manifest, source, publicKeyPath)
    if (!isDeepStrictEqual(nativeControlInstallFile(archive, binaryLimit), artifact)) throw new Error('archive changed during validation')
    let runner
    if (build.runner) {
      runner = nativeControlInstallFile(path.join(buildDir, 'control-upgrade-runner'), binaryLimit)
      if (build.runner.file !== 'control-upgrade-runner' || runner.mode !== 0o755 || runner.sha256 !== build.runner.sha256 || runner.bytes !== build.runner.bytes ||
          build.runner.version !== manifest.version || build.runner.signing_required !== true ||
          !isDeepStrictEqual(build.runner.source, { commit: manifest.source.commit, tree: manifest.source.tree }) || !isDeepStrictEqual(build.runner.platform, manifest.platform)) throw new Error('runner provenance mismatch')
      const reproduced = buildNativeUpgradeRunner(source, path.join(source, 'control-upgrade-runner.verify'), manifest.platform.arch)
      if (reproduced.sha256 !== runner.sha256) throw new Error('upgrade runner differs from exact archived source')
      fs.copyFileSync(path.join(buildDir, 'control-upgrade-runner'), path.join(work, 'control-upgrade-runner'), fs.constants.COPYFILE_EXCL)
      fs.chmodSync(path.join(work, 'control-upgrade-runner'), 0o755)
      if (!isDeepStrictEqual(nativeControlInstallFile(path.join(work, 'control-upgrade-runner'), binaryLimit), runner)) throw new Error('runner changed while copying')
    }
    origin.check()
    const result = { schema: 'cdnca.native-management.signed-build/v2',
      ...(build.installation_mode ? { installation_mode: build.installation_mode, previous_source_semantics: build.previous_source_semantics } : {}),
      source: manifest.source, version: manifest.version, built_at: manifest.built_at, file: 'native-management.tar',
      sha256: artifact.sha256, bytes: artifact.bytes, signing_required: false, ...(runner ? { runner: build.runner } : {}),
      ...(build.schema_gate ? { schema_gate: build.schema_gate } : {}) }
    fs.mkdirSync(output, { mode: 0o700 })
    fs.copyFileSync(archive, path.join(output, 'native-management.tar'), fs.constants.COPYFILE_EXCL); fs.chmodSync(path.join(output, 'native-management.tar'), 0o600)
    if (!isDeepStrictEqual(nativeControlInstallFile(path.join(output, 'native-management.tar'), binaryLimit), { ...artifact, mode: 0o600 })) throw new Error('archive changed while copying')
    fs.writeFileSync(path.join(output, 'release.manifest.json'), raw, { flag: 'wx', mode: 0o644 })
    fs.writeFileSync(path.join(output, 'release.manifest.sig'), signature.replace(/\n$/, '') + '\n', { flag: 'wx', mode: 0o644 })
    if (runner) { fs.copyFileSync(path.join(work, 'control-upgrade-runner'), path.join(output, 'control-upgrade-runner'), fs.constants.COPYFILE_EXCL); fs.chmodSync(path.join(output, 'control-upgrade-runner'), 0o755) }
    fs.writeFileSync(path.join(output, 'build.json'), encode(result), { flag: 'wx', mode: 0o600 })
    return result
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const keys = { '--build-dir': 'buildDir', '--remote-ref': 'remoteRef', '--signature': 'signaturePath', '--public-key': 'publicKeyPath', '--output-dir': 'outputDir' }, options = {}
    for (let index = 2; index < process.argv.length; index += 2) {
      const key = keys[process.argv[index]], value = process.argv[index + 1]
      if (!key || !value || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
      options[key] = value
    }
    console.log(encode(finalizeNativeReleaseSignature(options)))
  } catch (error) { console.error(`native release signature: ${error.message}`); process.exitCode = 1 }
}
