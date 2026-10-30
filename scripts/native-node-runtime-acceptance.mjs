#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { nativePayloadFiles } from './native-node-package.mjs'
import { runtimeELF } from './native-node-export.mjs'
import { verifySources } from '../edge/openresty/native/verify-sources.mjs'

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const native = 'edge/openresty/native'
// Non-Lua build-context inputs of the native Dockerfile: container path -> repository path.
// The exporter hashes exactly these into evidence/runtime-build-inputs.sha256.
const contextInputs = {
  '/source-contract/verify-sources.mjs': `${native}/verify-sources.mjs`,
  '/source-contract/sources.lock.json': `${native}/sources.lock.json`,
  '/source-contract/build-openresty.sh': `${native}/build-openresty.sh`,
  // resty.ipmatcher (firewall action engine), vendored at the container image's pin.
  '/source-contract/vendor/ipmatcher.lua': 'edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua',
  '/source-contract/patches': `${native}/patches`,
  '/native-node-export.mjs': 'scripts/native-node-export.mjs',
  // h3probe (HTTP/3 health probe) is built from the committed client module.
  '/h3probe-src/go.mod': 'edge/openresty/http3/client/client.mod',
  '/h3probe-src/go.sum': 'edge/openresty/http3/client/client.sum',
  '/h3probe-src/main.go': 'edge/openresty/http3/client/main.go',
}
const h3probeVersions = 'edge/openresty/http3/versions.env'
const h3probeModule = 'github.com/cdnca/cdnca/edge/openresty/http3/client'
// Committed runtime inputs bound into the acceptance. The Dockerfile and the smoke harness
// cannot hash themselves into the payload, so they are recorded from the candidate commit.
const runtimeInputs = [`${native}/Dockerfile`, ...Object.values(contextInputs), 'scripts/native-node-runtime-smoke.sh']
// Lua is copied verbatim by the Dockerfile (payload path -> source); the payload must equal the candidate sources.
export const luaSources = {
  'lua/share/cdnca/range/guard.lua': 'edge/openresty/range/guard.lua',
  'lua/share/cdnca/security/cdnca_waf.lua': 'edge/openresty/lua/cdnca_waf.lua',
  'lua/share/cdnca/security/cdnca_rule_interp.lua': 'edge/openresty/lua/cdnca_rule_interp.lua',
  'lua/share/cdnca/security/cdnca_banlist.lua': 'edge/openresty/lua/cdnca_banlist.lua',
  'lua/share/cdnca/dynroute/cdnca_site.lua': 'edge/openresty/dynroute/cdnca_site.lua',
  'lua/share/cdnca/dynroute/cdnca_site_admin.lua': 'edge/openresty/dynroute/cdnca_site_admin.lua',
  'lua/share/cdnca/dynroute/cdnca_tls.lua': 'edge/openresty/dynroute/cdnca_tls.lua', 'lua/share/cdnca/dynroute/cdnca_origin.lua': 'edge/openresty/dynroute/cdnca_origin.lua',
  'lua/share/cdnca/dynroute/cdnca_originauth.lua': 'edge/openresty/dynroute/cdnca_originauth.lua',
  'lua/share/cdnca/dynroute/cdnca_origintls.lua': 'edge/openresty/dynroute/cdnca_origintls.lua',
  'lua/share/cdnca/dynroute/cdnca_cache.lua': 'edge/openresty/dynroute/cdnca_cache.lua',
  'lua/share/cdnca/dynroute/cdnca_filters.lua': 'edge/openresty/dynroute/cdnca_filters.lua',
  'lua/share/cdnca/dynroute/cdnca_limits.lua': 'edge/openresty/dynroute/cdnca_limits.lua',
  'lua/share/cdnca/security/cc.lua': 'edge/openresty/ccv2/engine.lua',
  'lua/share/cdnca/httppolicy/engine.lua': 'edge/openresty/httppolicy/engine.lua',
  'lua/share/cdnca/firewallaction/engine.lua': 'edge/openresty/firewallaction/engine.lua',
  'lua/share/cdnca/siteaccess/engine.lua': 'edge/openresty/siteaccess/engine.lua',
  'lua/share/cdnca/errorpage/handler.lua': 'edge/openresty/errorpage/handler.lua',
  'lua/share/cdnca/originauth/engine.lua': 'edge/openresty/originauth/engine.lua',
  'lua/share/cdnca/originauth/crypto.lua': 'edge/openresty/originauth/crypto.lua',
  'lua/share/cdnca/dynroute/cdnca_dynroute.lua': 'edge/openresty/dynroute/cdnca_dynroute.lua',
  'lua/share/cdnca/dynroute/cdnca_security.lua': 'edge/openresty/dynroute/cdnca_security.lua',
  'lua/share/cdnca/dynroute/cdnca_managed_waf.lua': 'edge/openresty/dynroute/cdnca_managed_waf.lua',
  'lua/share/cdnca/dynroute/cdnca_rule_plan.lua': 'edge/openresty/dynroute/cdnca_rule_plan.lua',
  'lua/share/cdnca/dynroute/cdnca_bot.lua': 'edge/openresty/dynroute/cdnca_bot.lua',
  'lua/share/cdnca/dynroute/cdnca_telemetry.lua': 'edge/openresty/dynroute/cdnca_telemetry.lua',
  'lua/share/cdnca/dynroute/cdnca_webp.lua': 'edge/openresty/dynroute/cdnca_webp.lua',
  'lua/share/cdnca/dynroute/cdnca_webp_codec.lua': 'edge/openresty/dynroute/cdnca_webp_codec.lua',
  'lua/share/cdnca/sched302/cdnca_sched302.lua': 'edge/openresty/sched302/cdnca_sched302.lua',
  'lua/share/cdnca/security/cc_adaptive.lua': 'edge/openresty/ccadaptive/engine.lua',
  'lua/share/cdnca/security/url_auth.lua': 'edge/openresty/urlauth/engine.lua',
  'lua/share/cdnca/challenge/engine.lua': 'edge/openresty/challenge/engine.lua',
  'lua/share/cdnca/challenge/crypto.lua': 'edge/openresty/challenge/crypto.lua',
  'lua/share/cdnca/challenge/ip.lua': 'edge/openresty/challenge/ip.lua',
  'lua/l4geo/engine.lua': 'edge/openresty/l4geo/engine.lua',
  'lua/l4geo/cdnca_l4_geo.lua': 'edge/openresty/l4geo/cdnca_l4_geo.lua',
  'lua/share/cdnca/security/cdnca_iplib.lua': 'edge/openresty/iplib/cdnca_iplib.lua',
  'lua/l4geo/cdnca_iplib.lua': 'edge/openresty/iplib/cdnca_iplib.lua',
}
const smokeChecks = ['dynamic_modules', 'http1', 'http2', 'http3', 'http3_after_reload', 'lua', 'native_loader', 'new_worker', 'same_master_reload', 'stream_tcp']
// Built features the Agent and the edge configs rely on (build-openresty.sh configure flags).
const configureFlags = ['--with-http_ssl_module', '--with-http_v2_module', '--with-http_v3_module', '--with-stream', '--with-stream_ssl_module',
  '--with-stream_ssl_preread_module', '--with-stream_realip_module', '--with-compat', '--with-threads']
const runtimeMembers = ['runtime/openresty/bin/openresty', 'runtime/openresty/nginx/sbin/nginx', 'runtime/lib/ld-musl-x86_64.so.1', 'runtime/bin/h3probe']
const evidenceFiles = ['openresty-V.txt', 'runtime-apk-inventory.txt', 'runtime-build-inputs.sha256', 'runtime-export.json', 'runtime-sources.lock.json', 'source-verification.json']
const byPath = (a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0
function acceptanceDirectory(filename) {
  if (!path.isAbsolute(filename ?? '') || path.resolve(filename) !== filename ||
      !fs.lstatSync(filename).isDirectory() || fs.realpathSync(filename) !== filename) throw new Error('unsafe acceptance directory')
  return filename
}

function readAcceptanceFile(filename) {
  if (!path.isAbsolute(filename ?? '') || path.resolve(filename) !== filename || fs.realpathSync(filename) !== filename) throw new Error('unsafe acceptance file link')
  const stat = fs.lstatSync(filename)
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > 256 << 20) throw new Error('unsafe acceptance file')
  return fs.readFileSync(filename)
}

// Committed bytes of every file under members; the working tree must equal the candidate commit.
function committedSnapshot(commit, members) {
  const raw = execFileSync('git', ['ls-tree', '-r', '-z', commit, '--', ...members], { cwd: repository })
  const files = new Map()
  for (const record of raw.toString('utf8').split('\0').filter(Boolean)) {
    const match = /^100(?:644|755) blob ([0-9a-f]{40})\t(.+)$/.exec(record)
    if (!match) throw new Error('unsupported runtime source object')
    const bytes = readAcceptanceFile(path.join(repository, match[2]))
    if (createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') !== match[1]) throw new Error('working source differs from the candidate commit')
    files.set(match[2], bytes)
  }
  if (!members.every((member) => [...files.keys()].some((entry) => entry === member || entry.startsWith(`${member}/`)))) throw new Error('missing runtime source inputs')
  return files
}

// Build-context COPY sources of the Dockerfile, split into Lua payload members and the other inputs.
function dockerfileContext(dockerfile) {
  const lua = {}, other = {}
  for (const line of dockerfile.split('\n')) {
    if (/^ADD\s/i.test(line)) throw new Error('unsupported Dockerfile ADD')
    if (!/^COPY\s/.test(line) || /^COPY --from=/.test(line)) continue
    const parts = line.trim().split(/\s+/).slice(1), target = parts.at(-1), sources = parts.slice(0, -1)
    if (!sources.length || parts.some((part) => part.startsWith('--'))) throw new Error('unsupported Dockerfile COPY')
    for (const source of sources) {
      const destination = sources.length > 1 || target.endsWith('/') ? `${target.replace(/\/$/, '')}/${path.posix.basename(source)}` : target
      const member = destination.startsWith('/usr/local/share/cdnca/') ? `lua/share/cdnca/${destination.slice('/usr/local/share/cdnca/'.length)}`
        : destination.startsWith('/opt/cdnca/l4geo/') ? `lua/l4geo/${destination.slice('/opt/cdnca/l4geo/'.length)}` : null
      const map = member ? lua : other, key = member ?? destination
      if (Object.hasOwn(map, key)) throw new Error('duplicate Dockerfile COPY target')
      map[key] = source
    }
  }
  return { lua, other }
}

// Go buildinfo (Go 1.18+ inline format) from the .go.buildinfo section of a
// 64-bit little-endian ELF: what `go version -m` prints, read without Go.
export function goBuildInfo(bytes) {
  const fail = () => { throw new Error('h3probe has no readable Go buildinfo') }
  if (bytes.length < 64 || bytes.subarray(0, 4).toString('hex') !== '7f454c46' || bytes[4] !== 2 || bytes[5] !== 1) fail()
  const number = (offset) => { const value = Number(bytes.readBigUInt64LE(offset)); if (!Number.isSafeInteger(value)) fail(); return value }
  const sections = number(40), size = bytes.readUInt16LE(58), count = bytes.readUInt16LE(60), names = bytes.readUInt16LE(62)
  if (size !== 64 || !count || names >= count || sections + size * count > bytes.length) fail()
  const header = (index) => ({ name: bytes.readUInt32LE(sections + index * size), offset: number(sections + index * size + 24), size: number(sections + index * size + 32) })
  const table = header(names)
  let section
  for (let index = 0; index < count; index++) {
    const entry = header(index), start = table.offset + entry.name, end = bytes.indexOf(0, start)
    if (end > start && bytes.toString('latin1', start, end) === '.go.buildinfo') section = entry
  }
  if (!section || section.offset + section.size > bytes.length || section.size < 32) fail()
  const data = bytes.subarray(section.offset, section.offset + section.size)
  if (data.toString('latin1', 0, 14) !== '\xff Go buildinf:' || (data[15] & 2) === 0) fail()
  let position = 32
  const text = () => {
    let length = 0
    for (let shift = 0; ; shift += 7) {
      if (position >= data.length || shift > 28) fail()
      const byte = data[position++]
      length |= (byte & 0x7f) << shift
      if (byte < 0x80) break
    }
    if (position + length > data.length) fail()
    return data.toString('latin1', position, position += length)
  }
  const go = text(), raw = text()
  if (!/^go1\.\d+/.test(go) || raw.length < 33) fail()
  const info = { go, path: '', main: null, deps: [], settings: {}, replaced: false }
  for (const line of raw.slice(16, -16).split('\n').filter(Boolean)) {
    const [kind, ...fields] = line.split('\t')
    if (kind === 'path') info.path = fields[0]
    else if (kind === 'mod') info.main = { path: fields[0], version: fields[1] }
    else if (kind === 'dep') info.deps.push({ path: fields[0], version: fields[1], sum: fields[2] })
    else if (kind === '=>') info.replaced = true
    else if (kind === 'build') { const at = fields.join('\t').indexOf('='); info.settings[fields.join('\t').slice(0, at)] = fields.join('\t').slice(at + 1) }
  }
  return info
}

// h3probe must be exactly the committed client module built statically for
// linux/amd64 by the pinned Go builder (edge/openresty/http3/versions.env).
function h3probeProvenance(bytes, inputs, versionsBytes) {
  let elf
  try { elf = runtimeELF(bytes) } catch { elf = null }
  if (!elf || bytes.readUInt16LE(16) !== 2 || elf.interpreter || elf.dynamic) throw new Error('h3probe must be a static x86-64 executable')
  const env = Object.fromEntries(versionsBytes.toString('utf8').split('\n').filter((line) => /^[A-Z0-9_]+=/.test(line)).map((line) => line.split(/=(.*)/s).slice(0, 2)))
  const dockerfile = inputs.get(`${native}/Dockerfile`).toString('utf8')
  if (!/^golang@sha256:[0-9a-f]{64}$/.test(env.HTTP3_CLIENT_BUILDER ?? '') || !dockerfile.includes(`\nFROM ${env.HTTP3_CLIENT_BUILDER} AS h3probe\n`)) {
    throw new Error('h3probe builder differs from edge/openresty/http3/versions.env')
  }
  const info = goBuildInfo(bytes)
  if (info.go !== `go${env.HTTP3_CLIENT_GO_VERSION}`) throw new Error(`h3probe was built by ${info.go}, not Go ${env.HTTP3_CLIENT_GO_VERSION}`)
  const declared = /^module (\S+)$/m.exec(inputs.get('edge/openresty/http3/client/client.mod').toString('utf8'))?.[1]
  if (info.path !== h3probeModule || declared !== h3probeModule || info.main?.path !== h3probeModule || info.replaced) throw new Error('h3probe is not the committed client module')
  const sums = new Set(inputs.get('edge/openresty/http3/client/client.sum').toString('utf8').split('\n'))
  if (!info.deps.length || !info.deps.every((dep) => sums.has(`${dep.path} ${dep.version} ${dep.sum}`))) throw new Error('h3probe dependencies are not pinned by client.sum')
  const quic = info.deps.find((dep) => dep.path === 'github.com/quic-go/quic-go')
  if (quic?.version !== env.HTTP3_CLIENT_QUIC_GO_VERSION) throw new Error('h3probe quic-go differs from client.sum and versions.env')
  const settings = info.settings
  if (settings.CGO_ENABLED !== '0' || settings.GOOS !== 'linux' || settings.GOARCH !== 'amd64' || settings['-trimpath'] !== 'true' ||
      settings['-buildmode'] !== 'exe') throw new Error('h3probe build settings are not static linux/amd64 -trimpath')
  return { go: info.go, module: info.path, quic_go: quic.version, builder: env.HTTP3_CLIENT_BUILDER,
    deps: info.deps, settings }
}

function writeAcceptanceFile(filename, bytes) {
  const fd = fs.openSync(filename, 'wx', 0o444)
  const identity = fs.fstatSync(fd)
  try {
    fs.writeFileSync(fd, bytes)
    fs.fchmodSync(fd, 0o444)
    fs.fsyncSync(fd)
    fs.closeSync(fd)
  } catch (error) {
    try { fs.closeSync(fd) } catch { /* The failed close may already have closed it. */ }
    const current = fs.lstatSync(filename, { throwIfNoEntry: false })
    if (current?.dev === identity.dev && current?.ino === identity.ino) fs.unlinkSync(filename)
    throw error
  }
}
// Accept the runtime freshly built from this exact commit's runtime inputs, on its own
// evidence: committed inputs vs. what the exporter recorded, source signature and exact
// patch replay, nginx -V, the complete runtime/Lua inventory and all ten smoke checks.
// This is not a security review: the release owner rechecks the NGINX/OpenResty
// advisories before signing, and the release signature is the eligibility decision.
export function aggregateRuntimeAcceptance({ commit, payloadDir, smokeResult, sourceArchive }) {
  if (!/^[a-f0-9]{40}$/.test(commit ?? '')) throw new Error('invalid source commit')
  const payload = acceptanceDirectory(payloadDir)
  acceptanceDirectory(path.join(payload, 'evidence'))
  const output = path.join(payload, 'evidence/runtime-acceptance.json')
  if (fs.lstatSync(output, { throwIfNoEntry: false })) throw new Error('acceptance output already exists')
  const evidence = (name) => {
    try { return readAcceptanceFile(path.join(payload, 'evidence', name)) } catch { throw new Error(`missing or unsafe payload evidence: ${name}`) }
  }
  const tree = execFileSync('git', ['rev-parse', `${commit}^{tree}`], { cwd: repository, encoding: 'utf8' }).trim()
  const inputs = committedSnapshot(commit, runtimeInputs)
  const sources = committedSnapshot(commit, ['scripts/native-node-runtime-acceptance.mjs', 'scripts/native-node-package.mjs', h3probeVersions, ...new Set(Object.values(luaSources))])

  // The Dockerfile copies exactly the recorded inputs and the Lua mapping.
  const context = dockerfileContext(inputs.get(`${native}/Dockerfile`).toString('utf8'))
  if (!isDeepStrictEqual(context.other, contextInputs)) throw new Error('Dockerfile build context differs from the recorded runtime inputs')
  if (!isDeepStrictEqual(context.lua, luaSources)) throw new Error('Lua source mapping differs from the Dockerfile')
  const expectedInputs = Object.entries(contextInputs).flatMap(([target, member]) => [...inputs].filter(([name]) => name === member || name.startsWith(`${member}/`))
    .map(([name, bytes]) => `${sha256(bytes)}  ${target}${name.slice(member.length)}`)).sort()
  const recorded = evidence('runtime-build-inputs.sha256').toString('utf8')
  const recordedInputs = recorded.split('\n')
  if (recordedInputs.pop() !== '' || !recordedInputs.every((line) => /^[0-9a-f]{64} {2}\/[A-Za-z0-9_./+-]+$/.test(line)) ||
      !isDeepStrictEqual([...recordedInputs].sort(), expectedInputs)) throw new Error('recorded build inputs differ from the candidate commit')

  const lockBytes = inputs.get(`${native}/sources.lock.json`), lock = JSON.parse(lockBytes)
  if (lock.schema !== 'cdnca.native-openresty.sources/v1' || !/^\d+\.\d+\.\d+\.\d+$/.test(lock.source?.version ?? '') ||
      !/^\d+\.\d+\.\d+$/.test(lock.source?.nginx_core ?? '') || !/^[a-f0-9]{64}$/.test(lock.source?.sha256 ?? '') ||
      !Array.isArray(lock.patches) || !lock.patches.length) throw new Error('invalid runtime source lock')
  if (!evidence('runtime-sources.lock.json').equals(lockBytes)) throw new Error('payload source lock differs from the candidate commit')
  const built = JSON.parse(evidence('source-verification.json'))
  if (built.evidence !== 'source-only' || built.source_sha256 !== lock.source.sha256 || built.signer !== lock.source.signer?.fingerprint ||
      built.patches !== lock.patches.length) throw new Error('build source verification differs from the source lock')
  const nginxV = evidence('openresty-V.txt').toString('utf8')
  const configure = (/^configure arguments: (.*)$/m.exec(nginxV)?.[1] ?? '').split(/\s+/)
  if (!nginxV.startsWith(`nginx version: openresty/${lock.source.version}\n`) ||
      !new RegExp(`^built with OpenSSL ${(lock.build_base?.openssl ?? '-').replaceAll('.', '\\.')} `, 'm').test(nginxV) ||
      !configureFlags.every((flag) => configure.includes(flag)) ||
      !configure.some((flag) => /^--add-module=\S*\/cdnca-ja4$/.test(flag)) ||
      !configure.some((flag) => /^--add-module=\S*\/ngx_brotli$/.test(flag))) throw new Error('nginx -V differs from the locked build')

  const inventory = nativePayloadFiles(payload).filter((file) => /^(runtime|lua)\//.test(file.path))
  const lua = inventory.filter((file) => file.path.startsWith('lua/'))
  for (const [member, source] of Object.entries(luaSources)) {
    const entry = lua.find((file) => file.path === member)
    if (entry?.mode !== '0444' || entry.sha256 !== sha256(sources.get(source))) throw new Error(`payload Lua differs from its candidate source: ${member}`)
  }
  if (lua.length !== Object.keys(luaSources).length) throw new Error('payload Lua differs from its candidate sources')
  for (const member of runtimeMembers) {
    const entry = inventory.find((file) => file.path === member)
    if (entry?.mode !== '0555' || !entry.size) throw new Error(`missing or invalid runtime member: ${member}`)
  }
  if (inventory.find((file) => file.path === runtimeMembers[0]).sha256 !== inventory.find((file) => file.path === runtimeMembers[1]).sha256) throw new Error('OpenResty aliases differ')
  const h3probe = h3probeProvenance(readAcceptanceFile(path.join(payload, 'runtime/bin/h3probe')), inputs, sources.get(h3probeVersions))
  const files = inventory.map(({ path, sha256 }) => ({ path, sha256 }))
  const exported = JSON.parse(evidence('runtime-export.json'))
  if (exported.schema !== 'cdnca.native-node.runtime-export/v1' || !Array.isArray(exported.files) ||
      !isDeepStrictEqual([...exported.files].sort(byPath), files)) throw new Error('runtime export differs from the complete inventory')
  const smokeBytes = readAcceptanceFile(smokeResult), smoke = JSON.parse(smokeBytes)
  if (smoke.schema !== 'cdnca.native-node.runtime-smoke/v1' || smoke.status !== 'PASS' ||
      !isDeepStrictEqual(smoke.source, { commit, tree }) || !isDeepStrictEqual(Object.keys(smoke.checks ?? {}).sort(), smokeChecks) ||
      !smokeChecks.every((check) => smoke.checks[check] === 'PASS') || !Array.isArray(smoke.files) ||
      !isDeepStrictEqual([...smoke.files].sort(byPath), files)) throw new Error('fresh smoke source, checks or inventory mismatch')

  readAcceptanceFile(sourceArchive)
  const temporary = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'cdnca-runtime-acceptance-')))
  try {
    const source = verifySources(sourceArchive, path.join(temporary, 'source'))
    if (source.evidence !== 'source-only' || source.source_sha256 !== lock.source.sha256 || source.signer !== lock.source.signer.fingerprint ||
        source.patches !== lock.patches.length) throw new Error('source verification differs from the source lock')
  } finally { fs.rmSync(temporary, { recursive: true, force: true }) }

  const acceptance = { schema: 'cdnca.native-node.runtime-acceptance/v1', mode: 'fresh-build', source: { commit, tree },
    runtime: { openresty_version: lock.source.version, nginx_version: lock.source.nginx_core, source_sha256: lock.source.sha256,
      patch_manifest_sha256: sha256(lockBytes), release_eligible: true },
    build: { base: lock.build_base?.reference, script_sha256: sha256(inputs.get(`${native}/build-openresty.sh`)),
      inputs: [...inputs].map(([name, bytes]) => ({ path: name, sha256: sha256(bytes) })).sort(byPath),
      patches: lock.patches.map((patch) => ({ file: patch.file, sha256: patch.sha256 })), nginx_V: nginxV },
    evidence: Object.fromEntries(evidenceFiles.map((name) => [name, sha256(evidence(name))])),
    smoke: { sha256: sha256(smokeBytes), checks: smoke.checks },
    h3probe: { path: 'runtime/bin/h3probe', sha256: files.find((file) => file.path === 'runtime/bin/h3probe').sha256, ...h3probe },
    files,
    checks: Object.fromEntries(['source_signature', 'patches', 'build_inputs', 'configure', 'native_loader', 'h3probe', 'http1', 'http2', 'http3', 'stream', 'lua', 'reload'].map((name) => [name, 'PASS'])) }
  writeAcceptanceFile(output, JSON.stringify(acceptance, null, 2) + '\n')
  return acceptance
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const names = { '--source-commit': 'commit', '--payload-dir': 'payloadDir', '--smoke-result': 'smokeResult', '--source-archive': 'sourceArchive' }
  const options = {}, args = process.argv.slice(2)
  for (let index = 0; index < args.length; index += 2) {
    if (!Object.hasOwn(names, args[index]) || options[names[args[index]]] || !args[index + 1]) throw new Error('invalid acceptance arguments')
    options[names[args[index]]] = args[index + 1]
  }
  if (Object.keys(options).length !== 4) throw new Error('invalid acceptance arguments')
  console.log(JSON.stringify(aggregateRuntimeAcceptance(options)))
}
