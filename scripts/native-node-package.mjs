#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { createHash, createPublicKey, verify } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'

const schema = 'cdnca.native-node.release/v1'
const domain = Buffer.from(`${schema}\n`)
const objectID = /^[a-f0-9]{40}$/
const digest = /^[a-f0-9]{64}$/
const stableVersion = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
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
]
// Members that let the root packaging helper upgrade a native node in place.
const upgradeRequired = [
  'bin/cdnca-edge-agent-helper',
  ...['install', 'lib', 'preflight', 'rollback', 'uninstall', 'upgrade'].map((name) => `packaging/scripts/${name}.sh`),
  'packaging/systemd/cdnca-edge-agent.service', 'packaging/systemd/cdnca-edge-agent-root.service',
  'packaging/systemd/cdnca-edge-agent-helper.service', 'packaging/systemd/cdnca-edge-agent-helper.socket',
  'packaging/sysusers/cdnca-edge-agent.conf', 'packaging/tmpfiles/cdnca-edge-agent.conf',
  'packaging/tmpfiles/cdnca-edge-agent-root.conf', 'packaging/logrotate/cdnca-edge-agent',
  'packaging/config/agent.env', 'packaging/config/config.example.json', 'packaging/README.md',
  // Manifest v2 inputs verified by packaging install.sh and the helper.
  'upgrade/manifest', 'upgrade/manifest.sig', 'upgrade/package-signing.pem', 'evidence/edge-agent.spdx.json',
]
const upgradeMembers = new Set(upgradeRequired)
// runtime/ Lua (the OpenResty lualib, e.g. resty/ipmatcher.lua) is data.
const executableMember = (name) => name.startsWith('bin/') || name.startsWith('runtime/') && !name.endsWith('.lua') ||
  /^packaging\/scripts\/[a-z]+\.sh$/.test(name)

// The signed manifest v2 must describe exactly the packaged Agent and SBOM and
// verify under the packaged release key, otherwise the node could never be
// installed through (or upgraded by) the packaging transaction.
function verifyUpgradeInputs(root, files) {
  const read = (name) => fs.readFileSync(path.join(root, name))
  const entry = (name) => files.find((file) => file.path === name)
  const manifest = read('upgrade/manifest').toString('ascii')
  const lines = manifest.split('\n')
  const keys = ['manifest_version', 'release_sequence', 'version', 'artifact_path', 'artifact_sha256', 'artifact_size',
    'sbom_path', 'sbom_sha256', 'sbom_size', 'os', 'arch', 'source_repository', 'source_commit', 'build_time',
    'minimum_control_protocol', 'minimum_agent_protocol']
  if (!/^[\x20-\x7e\n]+$/.test(manifest) || lines.length !== 17 || lines[16] !== '' ||
      keys.some((key, index) => !lines[index].startsWith(`${key}=`))) throw new Error('upgrade manifest is not canonical manifest v2')
  const value = Object.fromEntries(keys.map((key, index) => [key, lines[index].slice(key.length + 1)]))
  const agent = entry('bin/edge-agent'), sbom = entry('evidence/edge-agent.spdx.json')
  if (value.manifest_version !== '2' || value.artifact_path !== 'edge-agent' || value.sbom_path !== 'edge-agent.spdx.json' ||
      value.os !== 'linux' || value.arch !== 'amd64' || value.artifact_sha256 !== agent.sha256 ||
      value.artifact_size !== String(agent.size) || value.sbom_sha256 !== sbom.sha256 || value.sbom_size !== String(sbom.size)) {
    throw new Error('upgrade manifest does not describe the packaged Agent and SBOM')
  }
  const key = createPublicKey(read('upgrade/package-signing.pem'))
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.from(manifest, 'ascii'), key, read('upgrade/manifest.sig'))) {
    throw new Error('upgrade manifest signature does not verify under the packaged release key')
  }
  return value
}

// Every payload member (no links, immutable modes, allowed paths), sorted by path.
// Runtime acceptance inventories the runtime/Lua part before the Agent is added.
export function nativePayloadFiles(directory) {
  const root = path.resolve(directory)
  if (!fs.lstatSync(root).isDirectory() || fs.realpathSync(root) !== root) throw new Error('unsafe payload directory')
  const files = []
  const walk = (relative = '') => {
    for (const name of fs.readdirSync(path.join(root, relative)).sort()) {
      const member = relative ? `${relative}/${name}` : name
      if (!/^[A-Za-z0-9_.+/-]+$/.test(member) || member.split('/').some((part) => part === '.' || part === '..') || member.length > 240) {
        throw new Error(`unsafe package member: ${member}`)
      }
      const filename = path.join(root, member), stat = fs.lstatSync(filename)
      if (stat.isSymbolicLink() || stat.isFile() && stat.nlink !== 1) throw new Error(`package contains a link: ${member}`)
      if (stat.isDirectory()) { walk(member); continue }
      if (!stat.isFile() || !(/^(bin\/edge-agent|runtime\/bin\/h3probe|runtime\/(openresty|lib|usr\/lib)\/.+|lua\/(share\/cdnca|l4geo)\/.+|evidence\/.+)$/.test(member) ||
          upgradeMembers.has(member))) {
        throw new Error(`unexpected package member: ${member}`)
      }
      const mode = stat.mode & 0o7777
      if (mode !== 0o444 && mode !== 0o555) throw new Error(`package mode must be immutable: ${member}`)
      if (stat.size > 256 << 20) throw new Error('package member exceeds size limit')
      files.push({ path: member, size: stat.size, mode: mode === 0o555 ? '0555' : '0444', sha256: sha256(fs.readFileSync(filename)) })
    }
  }
  walk()
  files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
  if (files.length > 8192 || files.reduce((sum, file) => sum + file.size, 0) > 768 << 20) throw new Error('package exceeds size limit')
  return files
}

export function createNativeNodeManifest(directory, metadata) {
  if (!stableVersion.test(metadata.version) || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(metadata.key_id ?? '') ||
      !objectID.test(metadata.source?.commit) || !objectID.test(metadata.source?.tree) ||
      metadata.platform?.os !== 'linux' || metadata.platform?.arch !== 'amd64' ||
      !/^\d+\.\d+\.\d+\.\d+$/.test(metadata.runtime?.openresty_version ?? '') ||
      !stableVersion.test(metadata.runtime?.nginx_version ?? '') ||
      !digest.test(metadata.runtime?.source_sha256) || !digest.test(metadata.runtime?.patch_manifest_sha256) ||
      metadata.runtime?.release_eligible !== true) throw new Error('invalid native node metadata')
  const root = path.resolve(directory), files = nativePayloadFiles(root)
  for (const name of [...required, ...upgradeRequired]) {
    const entry = files.find((file) => file.path === name)
    const mode = executableMember(name) ? '0555' : '0444'
    if (!entry || !entry.size || entry.mode !== mode) {
      throw new Error(`missing or invalid required member: ${name}`)
    }
  }
  verifyUpgradeInputs(root, files)
  if (files.find((file) => file.path === 'runtime/openresty/bin/openresty').sha256 !==
      files.find((file) => file.path === 'runtime/openresty/nginx/sbin/nginx').sha256) throw new Error('OpenResty aliases differ')
  return { schema, version: metadata.version, key_id: metadata.key_id,
    source: { commit: metadata.source.commit, tree: metadata.source.tree },
    platform: { os: 'linux', arch: 'amd64' }, runtime: { ...metadata.runtime }, files }
}

export function packageNativeNodeRelease(options) {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
  const { commit, remoteRef, version, keyID, payloadDir, outputDir } = options
  if (!objectID.test(commit) || !/^refs\/heads\/[a-zA-Z0-9_./-]+$/.test(remoteRef ?? '') ||
      !path.isAbsolute(payloadDir ?? '') || !path.isAbsolute(outputDir ?? '') || fs.existsSync(outputDir)) {
    throw new Error('invalid package arguments or output already exists')
  }
  const git = (...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', maxBuffer: 16 << 20 }).trim()
  const checkRemote = () => {
    if (git('ls-remote', '--exit-code', 'origin', remoteRef) !== `${commit}\t${remoteRef}`) throw new Error('source is not the exact pushed remote tip')
  }
  checkRemote()
  const tree = git('rev-parse', `${commit}^{tree}`)
  const acceptance = JSON.parse(fs.readFileSync(path.join(payloadDir, 'evidence/runtime-acceptance.json'), 'utf8'))
  if (acceptance.schema !== 'cdnca.native-node.runtime-acceptance/v1' ||
      acceptance.source?.commit !== commit || acceptance.source?.tree !== tree ||
      !['source_signature', 'patches', 'native_loader', 'h3probe', 'http1', 'http2', 'http3', 'stream', 'lua', 'reload'].every((name) => acceptance.checks?.[name] === 'PASS')) {
    throw new Error('complete runtime acceptance for this exact source is required')
  }
  const metadata = { version, key_id: keyID, source: { commit, tree }, platform: { os: 'linux', arch: 'amd64' }, runtime: acceptance.runtime }
  const manifest = createNativeNodeManifest(payloadDir, metadata)
  const lockedSource = execFileSync('git', ['show', `${commit}:edge/openresty/native/sources.lock.json`], { cwd: repo })
  const sourceLock = JSON.parse(lockedSource)
  if (sourceLock.schema !== 'cdnca.native-openresty.sources/v1' ||
      sha256(lockedSource) !== manifest.files.find((file) => file.path === 'evidence/runtime-sources.lock.json')?.sha256 ||
      metadata.runtime.patch_manifest_sha256 !== sha256(lockedSource) ||
      metadata.runtime.source_sha256 !== sourceLock.source?.sha256 ||
      metadata.runtime.openresty_version !== sourceLock.source?.version ||
      metadata.runtime.nginx_version !== sourceLock.source?.nginx_core) throw new Error('runtime does not match the pushed source lock')
  const runtimeFiles = manifest.files.filter((file) => /^(runtime|lua)\//.test(file.path)).map(({ path, sha256 }) => ({ path, sha256 }))
  const exported = JSON.parse(fs.readFileSync(path.join(payloadDir, 'evidence/runtime-export.json'), 'utf8'))
  const sameFiles = (files) => Array.isArray(files) && files.length === runtimeFiles.length &&
    new Set(files.map((file) => file.path)).size === files.length &&
    files.every((file) => runtimeFiles.some((expected) => expected.path === file.path && expected.sha256 === file.sha256))
  if (exported.schema !== 'cdnca.native-node.runtime-export/v1' || !sameFiles(exported.files) || !sameFiles(acceptance.files)) {
    throw new Error('runtime evidence does not match the complete payload')
  }
  const provenance = JSON.parse(fs.readFileSync(path.join(payloadDir, 'evidence/edge-agent.provenance.json'), 'utf8'))
  if (provenance.schema !== 'cdnca.edge.release-provenance/v1' || provenance.source_commit !== commit ||
      provenance.version !== version || provenance.arch !== 'amd64' ||
      provenance.artifact?.sha256 !== manifest.files.find((file) => file.path === 'bin/edge-agent').sha256) throw new Error('Agent provenance does not match the release')
  checkRemote()
  fs.mkdirSync(outputDir, { mode: 0o700 })
  fs.cpSync(payloadDir, path.join(outputDir, 'payload'), { recursive: true, dereference: false, errorOnExist: true })
  if (JSON.stringify(createNativeNodeManifest(path.join(outputDir, 'payload'), metadata)) !== JSON.stringify(manifest)) throw new Error('payload changed while copying')
  const raw = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
  fs.writeFileSync(path.join(outputDir, 'release.manifest.json'), raw, { flag: 'wx', mode: 0o444 })
  fs.writeFileSync(path.join(outputDir, 'release.signing-data'), Buffer.concat([domain, raw]), { flag: 'wx', mode: 0o444 })
  const result = { schema: 'cdnca.native-node.unsigned-build/v1', source: manifest.source, version,
    manifest_sha256: sha256(raw), signing_required: true }
  fs.writeFileSync(path.join(outputDir, 'build.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o444 })
  return result
}

export function finalizeNativeNodePackage({ buildDir, signaturePath, publicKeyPath }) {
  const raw = fs.readFileSync(path.join(buildDir, 'release.manifest.json'))
  const manifest = JSON.parse(raw)
  if (manifest.schema !== schema || raw.length > 2 << 20) throw new Error('invalid signed manifest')
  const encoded = fs.readFileSync(signaturePath, 'utf8').trim()
  if (!/^[A-Za-z0-9+/]{86}==$/.test(encoded)) throw new Error('invalid signature encoding')
  const signature = Buffer.from(encoded, 'base64'), key = createPublicKey(fs.readFileSync(publicKeyPath))
  if (key.asymmetricKeyType !== 'ed25519' || !verify(null, Buffer.concat([domain, raw]), key, signature)) throw new Error('invalid external signature')
  const payload = path.join(buildDir, 'payload')
  if (JSON.stringify(createNativeNodeManifest(payload, manifest)) !== JSON.stringify(manifest)) throw new Error('payload changed after signing')
  const archive = path.join(buildDir, 'cdnca-edge-agent.tar.gz')
  if (fs.existsSync(archive)) throw new Error('archive already exists; refusing to overwrite')
  const work = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-native-node-archive-')))
  try {
    fs.cpSync(payload, path.join(work, 'payload'), { recursive: true, dereference: false })
    const staging = path.join(work, 'payload')
    if (JSON.stringify(createNativeNodeManifest(staging, manifest)) !== JSON.stringify(manifest)) throw new Error('payload changed during finalization')
    fs.writeFileSync(path.join(staging, 'release.manifest.json'), raw, { mode: 0o444, flag: 'wx' })
    fs.writeFileSync(path.join(staging, 'release.manifest.sig'), encoded + '\n', { mode: 0o444, flag: 'wx' })
    const names = ['release.manifest.json', 'release.manifest.sig', ...manifest.files.map((file) => file.path)]
    for (const name of names) fs.utimesSync(path.join(staging, name), 0, 0)
    const list = path.join(work, 'members')
    fs.writeFileSync(list, names.join('\n') + '\n')
    const ownership = execFileSync('tar', ['--version'], { encoding: 'utf8' }).includes('bsdtar')
      ? ['--uid', '0', '--gid', '0', '--no-mac-metadata'] : ['--owner=0', '--group=0', '--numeric-owner']
    const tar = path.join(work, 'payload.tar')
    execFileSync('tar', ['--format=ustar', ...ownership, '-cf', tar, '-T', list], { cwd: staging, env: { ...process.env, COPYFILE_DISABLE: '1' } })
    fs.writeFileSync(archive, gzipSync(fs.readFileSync(tar), { level: 9 }), { flag: 'wx', mode: 0o444 })
    const bytes = fs.readFileSync(archive)
    fs.writeFileSync(path.join(buildDir, 'SHA256SUMS'), `${sha256(bytes)}  cdnca-edge-agent.tar.gz\n`, { flag: 'wx', mode: 0o444 })
    return { schema, source: manifest.source, version: manifest.version, sha256: sha256(bytes), bytes: bytes.length, manifest_sha256: sha256(raw) }
  } finally { fs.rmSync(work, { recursive: true, force: true }) }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const command = process.argv[2], options = {}
    const keys = { '--source-commit': 'commit', '--remote-ref': 'remoteRef', '--version': 'version',
      '--key-id': 'keyID', '--payload-dir': 'payloadDir', '--output-dir': 'outputDir',
      '--build-dir': 'buildDir', '--signature': 'signaturePath', '--public-key': 'publicKeyPath' }
    for (let index = 3; index < process.argv.length; index += 2) {
      const key = keys[process.argv[index]], value = process.argv[index + 1]
      if (!key || !value || options[key] !== undefined) throw new Error('unknown, missing or duplicate argument')
      options[key] = value
    }
    if (command !== 'prepare' && command !== 'finalize') throw new Error('expected prepare or finalize')
    console.log(JSON.stringify(command === 'prepare' ? packageNativeNodeRelease(options) : finalizeNativeNodePackage(options), null, 2))
  } catch (error) { console.error(error.message); process.exitCode = 1 }
}
