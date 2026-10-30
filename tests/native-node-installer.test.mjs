import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync, statSync, existsSync, readlinkSync, symlinkSync, lstatSync, realpathSync, copyFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { createServer } from 'node:net'
import { gzipSync } from 'node:zlib'
import { test } from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { hostEd25519Tool, withHostEd25519Pin } from './helpers/ed25519-tool-host.mjs'

// The installer pins the linux/amd64 tool; tests pin the host build instead and
// expose it where the management-side verifier passes its copy.
process.env.CDNCA_ED25519_TOOL_PATH = hostEd25519Tool().path
const pinnedInstaller = join(mkdtempSync(join(tmpdir(), 'cdnca-node-installer-pinned-')), 'install-node.sh')
writeFileSync(pinnedInstaller, withHostEd25519Pin(readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')))
const script = readFileSync(pinnedInstaller, 'utf8')
  .replace(/^main "\$@"\s*$/m, '')
const domain = 'cdnca.native-node.release/v1\n'
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const hash = (data) => createHash('sha256').update(data).digest('hex')
const luaPaths = [
  'runtime/openresty/lualib/resty/ipmatcher.lua',
  'lua/share/cdnca/range/guard.lua', 'lua/share/cdnca/security/cdnca_waf.lua', 'lua/share/cdnca/security/cdnca_rule_interp.lua', 'lua/share/cdnca/security/cdnca_banlist.lua', 'lua/share/cdnca/dynroute/cdnca_site.lua', 'lua/share/cdnca/dynroute/cdnca_site_admin.lua', 'lua/share/cdnca/dynroute/cdnca_tls.lua', 'lua/share/cdnca/dynroute/cdnca_origin.lua', 'lua/share/cdnca/dynroute/cdnca_originauth.lua', 'lua/share/cdnca/dynroute/cdnca_origintls.lua', 'lua/share/cdnca/dynroute/cdnca_cache.lua', 'lua/share/cdnca/dynroute/cdnca_filters.lua', 'lua/share/cdnca/dynroute/cdnca_limits.lua',
  'lua/share/cdnca/security/cc.lua', 'lua/share/cdnca/security/cc_adaptive.lua',
  'lua/share/cdnca/security/url_auth.lua', 'lua/share/cdnca/challenge/engine.lua',
  'lua/share/cdnca/challenge/crypto.lua', 'lua/share/cdnca/challenge/ip.lua',
  'lua/l4geo/engine.lua', 'lua/l4geo/cdnca_l4_geo.lua',
  'lua/share/cdnca/security/cdnca_iplib.lua', 'lua/l4geo/cdnca_iplib.lua',
  'lua/share/cdnca/httppolicy/engine.lua', 'lua/share/cdnca/firewallaction/engine.lua', 'lua/share/cdnca/siteaccess/engine.lua', 'lua/share/cdnca/errorpage/handler.lua', 'lua/share/cdnca/originauth/engine.lua', 'lua/share/cdnca/originauth/crypto.lua', 'lua/share/cdnca/dynroute/cdnca_dynroute.lua', 'lua/share/cdnca/sched302/cdnca_sched302.lua', 'lua/share/cdnca/dynroute/cdnca_telemetry.lua', 'lua/share/cdnca/dynroute/cdnca_webp.lua', 'lua/share/cdnca/dynroute/cdnca_webp_codec.lua', 'lua/share/cdnca/dynroute/cdnca_security.lua', 'lua/share/cdnca/dynroute/cdnca_managed_waf.lua', 'lua/share/cdnca/dynroute/cdnca_rule_plan.lua', 'lua/share/cdnca/dynroute/cdnca_bot.lua',
]
const elf = Buffer.alloc(80)
Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf)
elf.writeUInt16LE(3, 16)
elf.writeUInt16LE(62, 18)
const helperElf = Buffer.from(elf)
helperElf[79] = 1
const probeElf = Buffer.from(elf)
probeElf[78] = 1
// The signed packaging toolset and manifest v2 inputs that let the root helper
// upgrade a native node in place.
const packagingScripts = ['install', 'lib', 'preflight', 'rollback', 'uninstall', 'upgrade'].map((name) => `packaging/scripts/${name}.sh`)
const packagingData = [
  'packaging/systemd/cdnca-edge-agent.service', 'packaging/systemd/cdnca-edge-agent-root.service',
  'packaging/systemd/cdnca-edge-agent-helper.service', 'packaging/systemd/cdnca-edge-agent-helper.socket',
  'packaging/sysusers/cdnca-edge-agent.conf', 'packaging/tmpfiles/cdnca-edge-agent.conf',
  'packaging/tmpfiles/cdnca-edge-agent-root.conf', 'packaging/logrotate/cdnca-edge-agent',
  'packaging/config/agent.env', 'packaging/config/config.example.json', 'packaging/README.md',
]
const agentSBOM = '{"spdxVersion":"SPDX-2.3"}\n'
// Canonical manifest v2 for the fixture Agent and SBOM under a packaged key.
const upgradeManifest = Buffer.from([
  'manifest_version=2', 'release_sequence=7', 'version=1.2.3', 'artifact_path=edge-agent',
  `artifact_sha256=${hash(elf)}`, `artifact_size=${elf.length}`, 'sbom_path=edge-agent.spdx.json',
  `sbom_sha256=${hash(agentSBOM)}`, `sbom_size=${Buffer.byteLength(agentSBOM)}`, 'os=linux', 'arch=amd64',
  'source_repository=https://example.invalid/cdnca.git', `source_commit=${'a'.repeat(40)}`,
  'build_time=2026-07-22T00:00:00Z', 'minimum_control_protocol=1.0', 'minimum_agent_protocol=1.0', '',
].join('\n'))
const upgradeSignature = sign(null, upgradeManifest, privateKey)

function tar(members) {
  const chunks = []
  for (const member of members) {
    const body = Buffer.from(member.body)
    const header = Buffer.alloc(512)
    header.write(member.path, 0, 100)
    header.write((member.mode ?? 0o444).toString(8).padStart(7, '0') + '\0', 100)
    header.write('0000000\0', 108)
    header.write('0000000\0', 116)
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124)
    header.write('00000000000\0', 136)
    header.fill(0x20, 148, 156)
    header.write(member.type ?? '0', 156)
    header.write(member.link ?? '', 157, 100)
    header.write('ustar\0', 257)
    header.write('00', 263)
    const checksum = header.reduce((sum, value) => sum + value, 0)
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148)
    chunks.push(header, body, Buffer.alloc((512 - body.length % 512) % 512))
  }
  chunks.push(Buffer.alloc(1024))
  return Buffer.concat(chunks)
}

function fixture(options = {}) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-node-test.'))
  const files = [
    { path: 'bin/edge-agent', body: elf, mode: 0o555 },
    { path: 'runtime/openresty/nginx/sbin/nginx', body: elf, mode: 0o555 },
    { path: 'runtime/openresty/bin/openresty', body: elf, mode: 0o555 },
    { path: 'runtime/lib/ld-musl-x86_64.so.1', body: elf, mode: 0o555 },
    ...luaPaths.map((path) => ({ path, body: `-- ${path}\n`, mode: 0o444 })),
    { path: 'runtime/bin/h3probe', body: probeElf, mode: 0o555 },
    { path: 'bin/cdnca-edge-agent-helper', body: helperElf, mode: 0o555 },
    ...packagingScripts.map((path) => ({ path, body: `#!/bin/sh\n# ${path}\n`, mode: 0o555 })),
    ...packagingData.map((path) => ({ path, body: `${path}\n`, mode: 0o444 })),
    { path: 'evidence/edge-agent.spdx.json', body: agentSBOM, mode: 0o444 },
    { path: 'upgrade/manifest', body: upgradeManifest, mode: 0o444 },
    { path: 'upgrade/manifest.sig', body: upgradeSignature, mode: 0o444 },
    { path: 'upgrade/package-signing.pem', body: publicKey.export({ type: 'spki', format: 'pem' }), mode: 0o444 },
  ]
  options.files?.(files)
  const manifest = {
    schema: domain.trim(), key_id: 'fixture', version: '1.2.3',
    source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40) },
    platform: { os: 'linux', arch: 'amd64' },
    runtime: { openresty_version: '1.27.1.2', nginx_version: '1.27.1', source_sha256: 'c'.repeat(64), patch_manifest_sha256: 'd'.repeat(64), release_eligible: true },
    files: files.map((file) => ({ path: file.path, size: Buffer.byteLength(file.body), mode: file.mode.toString(8).padStart(4, '0'), sha256: hash(file.body) })),
  }
  options.manifest?.(manifest)
  const encoded = Buffer.from(options.encode ? options.encode(manifest) : JSON.stringify(manifest))
  const signature = sign(null, Buffer.concat([Buffer.from(options.domain ?? domain), encoded]), privateKey).toString('base64') + '\n'
  const members = [
    { path: 'release.manifest.json', body: encoded },
    { path: 'release.manifest.sig', body: signature }, ...files,
  ]
  options.members?.(members)
  const raw = Buffer.concat([tar(members), options.trailing ?? Buffer.alloc(0)])
  const compressed = Buffer.concat([gzipSync(raw), options.gzipTrailing ?? Buffer.alloc(0)])
  const trust = { version: 1, keys: [{ key_id: 'fixture', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }) }] }
  options.trust?.(trust)
  writeFileSync(join(root, 'package.tar.gz'), compressed, { mode: 0o600 })
  writeFileSync(join(root, 'trust.json'), JSON.stringify(trust), { mode: 0o600 })
  return { root, encoded, manifest, output: join(root, 'unpacked') }
}

function verify(value) {
  return spawnSync('bash', ['-c', `${script}\nverify_native_package "$1" "$2" "$3"`, 'test', join(value.root, 'package.tar.gz'), join(value.root, 'trust.json'), value.output], { encoding: 'utf8', timeout: 15000 })
}

test('fresh node installation requires iproute2 for automatic egress detection', () => {
  const missing = spawnSync('bash', ['-c', `${script}\ncommand() { [[ "$1" == -v && "$2" != ip ]]; }\nrequire_commands`], { encoding: 'utf8' })
  assert.notEqual(missing.status, 0, 'missing ip must trigger dependency installation')
  // nft stubbed present: the post-install nftables check (PJ-E04) is covered by node-installer-nftables.test.mjs.
  const installed = spawnSync('bash', ['-c', `${script}\napt-get() { printf '%s\\n' "$*"; }\nnft() { :; }\ninstall_dependencies`], { encoding: 'utf8' })
  assert.equal(installed.status, 0, installed.stderr)
  assert.match(installed.stdout, /install .*\biproute2\b/)
})

test('native verifier accepts the full signed package without executing its fixture ELF files', () => {
  const value = fixture()
  try {
    const result = verify(value)
    assert.equal(result.status, 0, result.stderr)
    const facts = JSON.parse(result.stdout)
    assert.equal(facts.manifest_sha256, hash(value.encoded))
    assert.equal(facts.version, '1.2.3')
    assert.equal(facts.openresty_version, '1.27.1.2')
    assert.deepEqual(readFileSync(join(value.output, 'bin/edge-agent')), elf)
    assert.equal(statSync(join(value.output, 'bin/edge-agent')).mode & 0o777, 0o555)
    assert.deepEqual(readFileSync(join(value.output, 'runtime/bin/h3probe')), probeElf)
    assert.equal(statSync(join(value.output, 'runtime/bin/h3probe')).mode & 0o777, 0o555)
    for (const path of luaPaths) assert.equal(statSync(join(value.output, path)).mode & 0o777, 0o444)
    for (const path of ['', 'runtime', 'runtime/openresty', 'lua/share/cdnca']) assert.equal(statSync(join(value.output, path)).mode & 0o777, 0o755)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('verification-only CLI checks a signed node package without enrollment or host service writes', () => {
  const value = fixture()
  try {
    const result = spawnSync('bash', [pinnedInstaller,
      '--verify-native-package', join(value.root, 'package.tar.gz'), join(value.root, 'trust.json'), value.output],
    { encoding: 'utf8', timeout: 15000 })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(JSON.parse(result.stdout).manifest_sha256, hash(value.encoded))
    // security_runtime (native) digests come from the verified signed inventory.
    const security = (name) => hash(`-- lua/share/cdnca/security/${name}.lua\n`)
    assert.deepEqual(JSON.parse(result.stdout).security_assets,
      { waf: security('cdnca_waf'), cc: security('cc'), adaptive: security('cc_adaptive') })
    assert.deepEqual(readFileSync(join(value.output, 'bin/edge-agent')), elf)
    const rejected = spawnSync('bash', [pinnedInstaller,
      '--verify-native-package', join(value.root, 'package.tar.gz')], { encoding: 'utf8', timeout: 15000 })
    assert.notEqual(rejected.status, 0)
    assert.match(rejected.stderr, /verification requires/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

const rejected = [
  ['wrong signature domain', { domain: 'other-domain\n' }],
  ['missing key', { manifest: (m) => { m.key_id = 'unknown' } }],
  ['duplicate trust key', { trust: (t) => { t.keys.push(t.keys[0]) } }],
  ['unknown schema', { manifest: (m) => { m.schema = 'legacy' } }],
  ['unknown field', { manifest: (m) => { m.unknown = true } }],
  ['duplicate JSON key', { encode: (m) => JSON.stringify(m).replace('"schema":', '"schema":"other","schema":') }],
  ['wrong architecture', { manifest: (m) => { m.platform.arch = 'arm64' } }],
  ['unsigned eligible false', { manifest: (m) => { m.runtime.release_eligible = false } }],
  ['invalid source commit', { manifest: (m) => { m.source.commit = 'latest' } }],
  ['non-stable version', { manifest: (m) => { m.version = '1.2.3-beta' } }],
  ['boolean file size', { manifest: (m) => { m.files[0].size = true } }],
  ['unsafe mode', { manifest: (m) => { m.files[0].mode = '4755' } }],
  ['signed non-ELF Agent', { files: (fs) => { fs[0].body = Buffer.from('#!/bin/sh\nexit 0\n') } }],
  ['signed wrong ELF architecture', { files: (fs) => { fs[0].body = Buffer.from(elf); fs[0].body.writeUInt16LE(183, 18) } }],
  ['signed wrong ELF endian', { files: (fs) => { fs[0].body = Buffer.from(elf); fs[0].body[5] = 2 } }],
  ['signed nonmatching OpenResty alias', { files: (fs) => { fs[2].body = Buffer.from(elf); fs[2].body[70] = 1 } }],
  ['signed executable Lua mode', { files: (fs) => { fs[4].mode = 0o555 } }],
  ['signed directory collision', { files: (fs) => { fs.push({ path: 'evidence/collision', body: 'x', mode: 0o444 }, { path: 'evidence/collision/child', body: 'x', mode: 0o444 }) } }],
  ['missing h3probe', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'runtime/bin/h3probe'), 1) } }],
  ['data-mode h3probe', { files: (fs) => { fs.find((f) => f.path === 'runtime/bin/h3probe').mode = 0o444 } }],
  ['non-ELF h3probe', { files: (fs) => { fs.find((f) => f.path === 'runtime/bin/h3probe').body = Buffer.from('#!/bin/sh\n') } }],
  ['unapproved runtime binary', { files: (fs) => { fs.push({ path: 'runtime/bin/other', body: probeElf, mode: 0o555 }) } }],
  ['missing runtime', { members: (members) => { members.splice(members.findIndex((m) => m.path === 'runtime/openresty/nginx/sbin/nginx'), 1) } }],
  ['missing required Lua', { manifest: (m) => { m.files = m.files.filter((f) => f.path !== luaPaths[0]) }, members: (ms) => { ms.splice(ms.findIndex((m) => m.path === luaPaths[0]), 1) } }],
  ...['httppolicy', 'firewallaction'].flatMap((module) => [
    [`missing required ${module} Lua`, { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === `lua/share/cdnca/${module}/engine.lua`), 1) } }],
    [`executable required ${module} Lua`, { files: (fs) => { fs.find((f) => f.path === `lua/share/cdnca/${module}/engine.lua`).mode = 0o555 } }],
  ]),
  ['missing required unit', { manifest: (m) => { m.files = m.files.filter((f) => !f.path.endsWith('.service')) }, members: (ms) => { ms.splice(ms.findIndex((m) => m.path.endsWith('.service')), 1) } }],
  ['missing packaging helper', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'bin/cdnca-edge-agent-helper'), 1) } }],
  ['data-mode packaging helper', { files: (fs) => { fs.find((f) => f.path === 'bin/cdnca-edge-agent-helper').mode = 0o444 } }],
  ['non-ELF packaging helper', { files: (fs) => { fs.find((f) => f.path === 'bin/cdnca-edge-agent-helper').body = Buffer.from('#!/bin/sh\n') } }],
  ['missing packaging upgrade script', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'packaging/scripts/upgrade.sh'), 1) } }],
  ['data-mode packaging script', { files: (fs) => { fs.find((f) => f.path === 'packaging/scripts/lib.sh').mode = 0o444 } }],
  ['missing root Agent unit', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'packaging/systemd/cdnca-edge-agent-root.service'), 1) } }],
  ['missing manifest v2', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'upgrade/manifest'), 1) } }],
  ['missing release key', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'upgrade/package-signing.pem'), 1) } }],
  ['missing Agent SBOM', { files: (fs) => { fs.splice(fs.findIndex((f) => f.path === 'evidence/edge-agent.spdx.json'), 1) } }],
  ['short manifest v2 signature', { files: (fs) => { fs.find((f) => f.path === 'upgrade/manifest.sig').body = Buffer.alloc(63, 0x5a) } }],
  ['unapproved packaging member', { files: (fs) => { fs.push({ path: 'packaging/scripts/extra.sh', body: '#!/bin/sh\n', mode: 0o555 }) } }],
  ['unapproved upgrade member', { files: (fs) => { fs.push({ path: 'upgrade/extra', body: 'x', mode: 0o444 }) } }],
  ['payload tampering', { members: (ms) => { ms.find((m) => m.path === 'bin/edge-agent').body = Buffer.from('changed') } }],
  ['duplicate member', { members: (ms) => { ms.push(ms[2]) } }],
  ['undeclared file', { members: (ms) => { ms.push({ path: 'evidence/extra', body: 'x' }) } }],
  ['package self trust', { members: (ms) => { ms.push({ path: 'artifacts.json', body: '{}' }) } }],
  ['relative escape', { members: (ms) => { ms[2].path = '../escape' } }],
  ['absolute escape', { members: (ms) => { ms[2].path = '/tmp/escape' } }],
  ['symlink', { members: (ms) => { ms[2].type = '2'; ms[2].link = '/tmp/escape'; ms[2].body = '' } }],
  ['hardlink', { members: (ms) => { ms[2].type = '1'; ms[2].link = 'release.manifest.json'; ms[2].body = '' } }],
  ['device', { members: (ms) => { ms[2].type = '3'; ms[2].body = '' } }],
  ['extended header', { members: (ms) => { ms[2].type = 'x' } }],
  ['tar trailing data', { trailing: Buffer.from('hidden bytes') }],
  ['second gzip stream', { gzipTrailing: gzipSync(Buffer.alloc(1024)) }],
]
for (const [name, options] of rejected) {
  test(`native verifier rejects ${name} before writing a destination`, () => {
    const value = fixture(options)
    try {
      const result = verify(value)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /native package rejected/)
      assert.equal(readdirSync(value.root).includes('unpacked'), false)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('native verifier never overwrites an existing destination', () => {
  const value = fixture()
  try {
    mkdirSync(value.output)
    writeFileSync(join(value.output, 'owned'), 'unchanged')
    const result = verify(value)
    assert.notEqual(result.status, 0)
    assert.equal(readFileSync(join(value.output, 'owned'), 'utf8'), 'unchanged')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('node bootstrap rejects insecure package or trust transport', () => {
  const result = spawnSync('bash', ['-c', `${script}\nvalid_url http://control.example/downloads/artifacts.json`], { encoding: 'utf8' })
  assert.notEqual(result.status, 0)
})

// Shell orchestration tests substitute commands and absolute installation paths;
// the fake executables are never evidence of a Linux runtime smoke test.
function shellFixture() {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-native-shell-test.'))
  let isolated = script
  for (const prefix of ['/usr/local', '/etc', '/opt', '/var/lib', '/var/log', '/run', '/usr/sbin/nginx']) {
    isolated = isolated.replace(new RegExp(`${prefix}(?=/|["'\\s;]|$)`, 'g'), join(root, prefix.slice(1)))
  }
  // Packaging and helper install targets only; /usr/lib in runtime library
  // search paths stays untouched.
  for (const prefix of ['/usr/lib/cdnca-edge-agent', '/usr/lib/systemd/system', '/usr/libexec/cdnca-edge-agent-helper', '/usr/libexec/cdnca-edge-agent']) {
    isolated = isolated.replaceAll(`"${prefix}`, `"${join(root, prefix.slice(1))}`)
  }
  const file = (path, contents, mode = 0o600) => {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, contents, { mode })
    return target
  }
  const run = (body, env = {}) => spawnSync('bash', ['-c', `${isolated}\n${body}`, 'fixture', root], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 15000 })
  return { root, file, run }
}

for (const helper of ['download_json_verified', 'download_certificate_verified']) {
  test(`${helper} bounds external trust material downloads before parsing`, () => {
    const value = shellFixture()
    try {
      mkdirSync(join(value.root, 'temporary'))
      const result = value.run(`
TEMP_DIR="$1/temporary"
curl_download() {
  [[ "$*" == *'--max-filesize 65536'* ]] || return 64
  while [[ "$1" != --output ]]; do shift; done
  printf '%s' '{"version":1,"keys":[{}]}' >"$2"
}
openssl() { return 0; }
${helper} https://fixture.invalid/trust https://fixture.invalid/trust "$1/downloaded" ${helper === 'download_json_verified' ? "'.version == 1'" : ''}
`)
      assert.equal(result.status, 0, result.stderr)
      assert.equal(existsSync(join(value.root, 'downloaded')), true)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

const runtimeFlags = '--with-stream_realip_module --with-http_v2_module --with-http_v3_module --with-http_ssl_module --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module'
const linuxLinkStub = `
ln() {
  if [[ "$1" == -sT ]]; then
    shift
    [[ ! -e "$2" && ! -L "$2" ]] || return 1
    command ln -s "$@"
  else command ln "$@"; fi
}
`
for (const failure of ['', 'version', 'module', 'syntax', 'agent_source', 'h3probe']) {
  test(`native preflight uses staged loader before activation and enrollment (${failure || 'success'})`, () => {
    const value = shellFixture()
    try {
      value.file('stage/runtime/lib/ld-musl-x86_64.so.1', `#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$PROBE_CALLS"
[[ "$1" == --library-path && "$3" == "$FIXTURE_ROOT/stage/runtime/openresty/nginx/sbin/nginx" ]] || exit 90
[[ "$2" == "$EXPECTED_RUNTIME_LIBRARIES" ]] || { printf 'OpenResty-specific libraries must precede generic libraries\\n' >&2; exit 92; }
case "$4" in
  -V) printf '%s\\n' 'nginx version: openresty/${failure === 'version' ? '1.0.0.1' : '1.27.1.2'}' 'configure arguments: ${failure === 'module' ? runtimeFlags.replace('--with-http_v3_module', '') : runtimeFlags}' ;;
  -t)
    [[ "$5" == -p && "$7" == -c ]] || exit 93
    grep -Fxq 'user nobody nogroup;' "$8" || exit 96
    : >"$6/logs/access.log" || exit 94
    log_mode=$(stat -c '%a' "$6/logs" 2>/dev/null || stat -f '%Lp' "$6/logs")
    [[ "$log_mode" == 700 ]] || exit 95
    exit ${failure === 'syntax' ? '1' : '0'} ;;
  *) exit 91 ;;
esac
`, 0o700)
      value.file('stage/bin/edge-agent', `#!/usr/bin/env bash
printf '%s\\n' '{"event":"version","agent_version":"1.2.3","build_id":"${(failure === 'agent_source' ? 'b' : 'a').repeat(40)}"}'
`, 0o700)
      value.file('stage/runtime/bin/h3probe', `#!/usr/bin/env bash
[[ "$*" == version ]] || exit 97
printf '%s\\n' '${failure === 'h3probe' ? '{"schema":"other"}' : '{"schema":"cdnca.h3probe/v1","go":"go1.24.5","quic_go":"v0.54.0"}'}'
`, 0o700)
      value.file('temporary/native-facts.json', JSON.stringify({ source: { commit: 'a'.repeat(40) } }))
      const result = value.run(`
timeout() { shift; "$@"; }
id() { printf 65534; }
getent() { printf 'nogroup:x:65534:\\n'; }
TEMP_DIR="$1/temporary"; NATIVE_STAGE="$1/stage"; OPENRESTY_VERSION=1.27.1.2; NATIVE_VERSION=1.2.3
preflight_native_runtime
printf 'activated\\n' >>"$1/side-effects"
printf 'enrolled\\n' >>"$1/side-effects"
`, { PROBE_CALLS: join(value.root, 'probe-calls'), FIXTURE_ROOT: value.root, EXPECTED_RUNTIME_LIBRARIES: ['openresty/luajit/lib', 'openresty/openssl3/lib', 'openresty/pcre2/lib', 'lib', 'usr/lib'].map((path) => join(value.root, 'stage/runtime', path)).join(':') })
      assert.equal(result.status === 0, failure === '', result.stderr)
      const calls = readFileSync(join(value.root, 'probe-calls'), 'utf8')
      assert.ok(calls.includes('/stage/runtime/lib:'))
      assert.ok(calls.includes('/stage/runtime/openresty/openssl3/lib:'))
      assert.ok(calls.includes(' -V'))
      assert.equal(calls.includes(' -t'), !['version', 'module'].includes(failure))
      assert.equal(existsSync(join(value.root, 'side-effects')), failure === '')
      assert.equal(existsSync(join(value.root, 'usr/local/openresty')), false)
      assert.equal(existsSync(join(value.root, 'var/lib/site-runtime/current')), false)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const [name, uid, gid, group, lookup] of [
  ['root nobody UID', '0', '65534', '65534', '0'],
  ['wrong nobody primary GID', '65534', '0', '65534', '0'],
  ['root nogroup GID', '65534', '65534', '0', '0'],
  ['failed nogroup lookup', '65534', '65534', '65534', '2'],
]) {
  test(`native syntax probe rejects ${name} before invoking runtime or enrollment`, () => {
    const value = shellFixture()
    try {
      mkdirSync(join(value.root, 'temporary'))
      const result = value.run(`
id() { if [[ "$1" == -u ]]; then printf '%s' "$FIXTURE_PROBE_UID"; else printf '%s' "$FIXTURE_PROBE_GID"; fi; }
getent() { printf 'nogroup:x:%s:\\n' "$FIXTURE_PROBE_GROUP"; return "$FIXTURE_PROBE_LOOKUP"; }
timeout() { printf invoked >"$FIXTURE_ROOT/runtime-called"; }
TEMP_DIR="$1/temporary"; NATIVE_STAGE="$1/stage"; OPENRESTY_VERSION=1.27.1.2; NATIVE_VERSION=1.2.3
preflight_native_runtime
printf enrolled >"$1/side-effects"
`, { FIXTURE_ROOT: value.root, FIXTURE_PROBE_UID: uid, FIXTURE_PROBE_GID: gid, FIXTURE_PROBE_GROUP: group, FIXTURE_PROBE_LOOKUP: lookup })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /native syntax probe requires nobody with UID\/GID 65534/)
      assert.equal(existsSync(join(value.root, 'runtime-called')), false)
      assert.equal(existsSync(join(value.root, 'side-effects')), false)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const existing of ['', '/etc/cdnca-edge-agent/identity', '/usr/local/openresty', '/opt/cdnca-node', '/var/lib/site-runtime']) {
  test(`blank host gate rejects prior state before any installation (${existing || 'blank fixture'})`, () => {
    const value = shellFixture()
    try {
      value.file('etc/os-release', 'ID=ubuntu\nVERSION_ID="24.04"\n')
      mkdirSync(join(value.root, 'run/systemd/system'), { recursive: true })
      mkdirSync(join(value.root, 'run/lock'), { recursive: true })
      if (existing) mkdirSync(join(value.root, existing), { recursive: true })
      const result = value.run(`
uname() { if [[ "$1" == -s ]]; then printf Linux; else printf x86_64; fi; }
systemctl() { printf 'not-found\\n'; }
flock() { return 0; }
stat() { printf '0:1:600\\n'; }
assert_blank_host
printf passed
`)
      assert.equal(result.status === 0, existing === '', result.stderr)
      if (existing) {
        assert.match(result.stderr, /first install refused/)
        assert.equal(existsSync(join(value.root, existing)), true)
      }
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const failure of [false, true]) {
  test(`first-install package links ${failure ? 'roll back on failure without deleting identity' : 'point to the immutable release'}`, () => {
    const value = shellFixture()
    try {
      value.file('stage/bin/edge-agent', 'verified fixture')
      value.file('temporary/artifacts.json', '{}')
      value.file('temporary/gateway-ca.pem', 'fixture certificate')
      for (const name of ['control-execution.json', 'edge-execution.json', 'download-ca.pem']) value.file(`temporary/upgrade-trust/${name}`, name, 0o400)
      mkdirSync(join(value.root, 'opt'), { recursive: true })
      mkdirSync(join(value.root, 'etc'), { recursive: true })
      const result = value.run(`
${linuxLinkStub}
mv() { if [[ "$1" == -T ]]; then shift; fi; command mv "$@"; }
TEMP_DIR="$1/temporary"; NATIVE_STAGE="$1/stage"; NATIVE_MANIFEST_SHA=${'a'.repeat(64)}
ARTIFACT_TRUST_FILE="$1/temporary/artifacts.json"; GATEWAY_ROOT_CA_FILE="$1/temporary/gateway-ca.pem"
activate_native_package
mkdir -m 0700 "$IDENTITY_DIR"
printf retained >"$IDENTITY_DIR/identity.json"
ENROLLMENT_ATTEMPTED=true
${failure ? 'exit 1' : 'exit 0'}
`)
      assert.equal(result.status, failure ? 1 : 0, result.stderr)
      const native = join(value.root, 'opt/cdnca-node')
      assert.equal(existsSync(join(native, 'releases', 'a'.repeat(64), 'bin/edge-agent')), true)
      assert.equal(existsSync(join(native, 'previous')), false)
      assert.equal(existsSync(join(native, 'current')), !failure)
      assert.equal(existsSync(join(value.root, 'usr/local/openresty')), false) // the tiny fixture omits runtime files
      if (!failure) {
        assert.equal(readlinkSync(join(native, 'current')), `releases/${'a'.repeat(64)}`)
        assert.equal(readlinkSync(join(value.root, 'usr/local/openresty')), `${native}/current/runtime/openresty`)
        assert.equal(statSync(native).mode & 0o777, 0o755)
        assert.equal(statSync(join(native, 'releases')).mode & 0o777, 0o755)
      } else assert.match(result.stderr, /token may already be consumed/)
      if (failure) assert.throws(() => lstatSync(join(value.root, 'usr/local/openresty')), { code: 'ENOENT' })
      assert.equal(readFileSync(join(value.root, 'etc/cdnca-edge-agent/identity/identity.json'), 'utf8'), 'retained')
      for (const path of ['trust/control-execution.json', 'trust/edge-execution.json', 'tls/upgrade-download-ca.pem']) {
        assert.equal(statSync(join(value.root, 'etc/cdnca-edge-agent', path)).mode & 0o777, 0o400, path)
      }
      assert.equal(existsSync(join(value.root, 'var/lib/site-runtime/current')), false)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('activation refuses a new global runtime directory without placing a link inside it', () => {
  const value = shellFixture()
  try {
    value.file('stage/bin/edge-agent', 'verified fixture')
    value.file('temporary/artifacts.json', '{}')
    value.file('temporary/gateway-ca.pem', 'fixture certificate')
    value.file('usr/local/openresty/existing', 'preserve')
    mkdirSync(join(value.root, 'opt'), { recursive: true })
    mkdirSync(join(value.root, 'etc'), { recursive: true })
    const result = value.run(`
${linuxLinkStub}
mv() { if [[ "$1" == -T ]]; then shift; fi; command mv "$@"; }
TEMP_DIR="$1/temporary"; NATIVE_STAGE="$1/stage"; NATIVE_MANIFEST_SHA=${'a'.repeat(64)}
ARTIFACT_TRUST_FILE="$1/temporary/artifacts.json"; GATEWAY_ROOT_CA_FILE="$1/temporary/gateway-ca.pem"
activate_native_package
`)
    assert.notEqual(result.status, 0)
    assert.deepEqual(readdirSync(join(value.root, 'usr/local/openresty')), ['existing'])
    assert.equal(readFileSync(join(value.root, 'usr/local/openresty/existing'), 'utf8'), 'preserve')
    assert.equal(existsSync(join(value.root, 'opt/cdnca-node/current')), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('native verifier rejects linked external trust without replacing its target', () => {
  const value = fixture()
  try {
    const original = readFileSync(join(value.root, 'trust.json'))
    writeFileSync(join(value.root, 'original.json'), original)
    rmSync(join(value.root, 'trust.json'))
    symlinkSync('original.json', join(value.root, 'trust.json'))
    assert.notEqual(verify(value).status, 0)
    assert.deepEqual(readFileSync(join(value.root, 'original.json')), original)
    assert.equal(existsSync(value.output), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

const rootUnit = readFileSync(new URL('../agents/edge-agent/packaging/systemd/cdnca-edge-agent-root.service', import.meta.url), 'utf8')
for (const failure of ['', 'restart', 'crash-loop', 'unit-differs']) {
  test(`service setup starts the packaged root Agent unit ${failure ? `and fails closed (${failure})` : 'and requires stable activity'}`, () => {
    const value = shellFixture()
    try {
      value.file('release/packaging/systemd/cdnca-edge-agent-root.service', rootUnit, 0o444)
      value.file('usr/lib/systemd/system/cdnca-edge-agent.service', failure === 'unit-differs' ? rootUnit + '# drift\n' : rootUnit, 0o644)
      value.file('etc/systemd/system/unrelated.service', 'preserve')
      const result = value.run(`
NATIVE_RELEASE="$1/release"
PACKAGING_INSTALLED=true
sleep() { :; }
journalctl() { :; }
# A current systemd (tests/systemd-compat.test.mjs covers older ones).
systemd_compat_knows() { return 0; }; systemd_compat_apply() { :; }
systemctl() {
  printf '%s\\n' "$*" >>"$NATIVE_SYSTEMCTL_TEST_LOG"
  case "$1" in
    restart) ${failure === 'restart' ? 'return 1' : ':'} ;;
    show) printf '%s\\n' ${failure === 'crash-loop' ? '1' : '0'} ;;
  esac
}
setup_service
`, { NATIVE_SYSTEMCTL_TEST_LOG: join(value.root, 'systemctl-calls') })
      assert.equal(result.status === 0, failure === '', result.stderr)
      const calls = existsSync(join(value.root, 'systemctl-calls')) ? readFileSync(join(value.root, 'systemctl-calls'), 'utf8') : ''
      // The Agent unit is never written to /etc, where it would shadow the
      // packaged unit and run a binary the helper does not upgrade.
      assert.equal(existsSync(join(value.root, 'etc/systemd/system/cdnca-edge-agent.service')), false)
      assert.equal(readFileSync(join(value.root, 'usr/lib/systemd/system/cdnca-edge-agent.service'), 'utf8'), failure === 'unit-differs' ? rootUnit + '# drift\n' : rootUnit)
      if (failure === 'unit-differs') {
        assert.match(result.stderr, /packaged root Agent unit is missing or differs/)
        assert.equal(calls.includes('enable cdnca-edge-agent'), false)
      } else {
        assert.ok(calls.includes('enable cdnca-edge-agent\n'))
      }
      // No OpenResty unit: the Agent's dynamic routing runtime owns the master.
      assert.equal(calls.includes('cdnca-openresty-native'), false)
      assert.equal(existsSync(join(value.root, 'etc/systemd/system/cdnca-openresty-native.service')), false)
      if (failure === '') {
        assert.ok(calls.split('is-active --quiet cdnca-edge-agent').length - 1 >= 5, 'stability requires repeated samples')
      } else {
        if (failure === 'crash-loop') assert.match(result.stderr, /did not become stably active/)
        assert.ok(calls.includes('stop cdnca-edge-agent\n'))
        assert.ok(calls.includes('disable cdnca-edge-agent\n'))
      }
      assert.equal(readFileSync(join(value.root, 'etc/systemd/system/unrelated.service'), 'utf8'), 'preserve')
      assert.equal(existsSync(join(value.root, 'var/lib/site-runtime/current')), false)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const name of ['cdnca-edge-agent.service']) {
  test(`service publication refuses an existing ${name} even after the blank-host check`, () => {
    const value = shellFixture()
    try {
      value.file(`etc/systemd/system/${name}`, 'do not replace\n')
      const result = value.run(`
NATIVE_RELEASE="$1/release"
systemctl() { return 0; }
setup_service
`)
      assert.notEqual(result.status, 0)
      assert.equal(readFileSync(join(value.root, 'etc/systemd/system', name), 'utf8'), 'do not replace\n')
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const failure of [false, true]) {
  test(`packaging install runs the signed release toolset as root ${failure ? 'and stops the Agent on failure' : ''}`, () => {
    const value = shellFixture()
    try {
      value.file('release/packaging/scripts/install.sh', `#!/usr/bin/env bash
printf '%s\\n' "$*" >"$FIXTURE_ROOT/install-args"
${failure ? 'exit 1' : `mkdir -p "$FIXTURE_ROOT/usr/lib/cdnca-edge-agent/versions/1.2.3"
ln -s versions/1.2.3 "$FIXTURE_ROOT/usr/lib/cdnca-edge-agent/current"`}
`, 0o755)
      const result = value.run(`
NATIVE_RELEASE="$1/release"; NATIVE_VERSION=1.2.3
systemctl() { printf '%s\\n' "$*" >>"$FIXTURE_ROOT/systemctl-calls"; }
install_agent_packaging
`, { FIXTURE_ROOT: value.root })
      assert.equal(result.status === 0, !failure, result.stderr)
      const release = join(value.root, 'release')
      assert.equal(readFileSync(join(value.root, 'install-args'), 'utf8'),
        `--runtime-identity root --artifact ${release}/bin/edge-agent --sbom ${release}/evidence/edge-agent.spdx.json ` +
        `--manifest ${release}/upgrade/manifest --signature ${release}/upgrade/manifest.sig --public-key ${release}/upgrade/package-signing.pem\n`)
      if (failure) {
        assert.match(result.stderr, /signed Agent packaging install failed; enrollment was not attempted/)
        assert.match(readFileSync(join(value.root, 'systemctl-calls'), 'utf8'), /stop cdnca-edge-agent/)
      }
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

for (const failure of ['', 'version', 'key-init', 'probe']) {
  test(`packaging helper is started and verified before enrollment (${failure || 'success'})`, () => {
    const value = shellFixture()
    try {
      value.file('release/bin/cdnca-edge-agent-helper', `#!/bin/sh\n[ "$1" = key-init ] || exit 64\nexit ${failure === 'key-init' ? 1 : 0}\n`, 0o555)
      value.file('release/upgrade/manifest', `manifest_version=2\nrelease_sequence=1\nversion=${failure === 'version' ? '9.9.9' : '1.2.3'}\n`, 0o444)
      for (const unit of ['cdnca-edge-agent-helper.service', 'cdnca-edge-agent-helper.socket']) value.file(`release/packaging/systemd/${unit}`, `${unit}\n`, 0o444)
      mkdirSync(join(value.root, 'usr/lib/systemd/system'), { recursive: true })
      mkdirSync(join(value.root, 'usr/libexec'), { recursive: true })
      const result = value.run(`
NATIVE_RELEASE="$1/release"; NATIVE_VERSION=1.2.3
systemctl() { printf '%s\\n' "$*" >>"$FIXTURE_ROOT/systemctl-calls"; }
probe_packaging_helper() { printf '%s\\n' "$*" >"$FIXTURE_ROOT/probe-args"; return ${failure === 'probe' ? 1 : 0}; }
# A current systemd (tests/systemd-compat.test.mjs covers older ones).
systemd_compat_knows() { return 0; }; systemd_compat_apply() { :; }
start_packaging_helper
`, { FIXTURE_ROOT: value.root })
      assert.equal(result.status === 0, failure === '', result.stderr)
      const calls = existsSync(join(value.root, 'systemctl-calls')) ? readFileSync(join(value.root, 'systemctl-calls'), 'utf8') : ''
      if (failure === 'version') {
        assert.match(result.stderr, /signed upgrade manifest version differs/)
        assert.equal(existsSync(join(value.root, 'usr/libexec/cdnca-edge-agent-helper')), false)
        return
      }
      assert.equal(statSync(join(value.root, 'usr/libexec/cdnca-edge-agent-helper')).mode & 0o777, 0o555)
      for (const unit of ['cdnca-edge-agent-helper.service', 'cdnca-edge-agent-helper.socket']) {
        // A failed bring-up removes the helper units it installed.
        if (failure) assert.equal(existsSync(join(value.root, 'usr/lib/systemd/system', unit)), false, unit)
        else assert.equal(statSync(join(value.root, 'usr/lib/systemd/system', unit)).mode & 0o777, 0o644, unit)
      }
      if (failure === 'key-init') {
        assert.match(result.stderr, /receipt key initialization failed/)
        assert.equal(calls.includes('enable --now'), false)
      }
      if (failure === '' || failure === 'probe') {
        assert.ok(calls.includes('enable --now cdnca-edge-agent-helper.socket\n'))
        assert.equal(readFileSync(join(value.root, 'probe-args'), 'utf8'),
          `${join(value.root, 'run/cdnca-edge-agent/helper.sock')} ${join(value.root, 'etc/cdnca-edge-agent/helper-receipt-public.json')} 1.2.3 ${join(value.root, 'etc/cdnca-edge-agent/trust/installer-receipt.json')}\n`)
      }
      if (failure === 'probe') {
        assert.match(result.stderr, /node upgrades cannot be enabled/)
        assert.ok(calls.includes('disable cdnca-edge-agent-helper.socket\n'))
      }
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

const builderPath = process.env.NATIVE_NODE_BUILDER ?? fileURLToPath(new URL('../scripts/native-node-package.mjs', import.meta.url))
test('installer accepts the actual native package builder USTAR/signature output', { skip: !existsSync(builderPath) }, async () => {
  const { createNativeNodeManifest, finalizeNativeNodePackage } = await import(pathToFileURL(builderPath))
  const value = fixture()
  try {
    assert.equal(verify(value).status, 0)
    const build = join(realpathSync(value.root), 'build'), payload = join(build, 'payload')
    mkdirSync(payload, { recursive: true })
    for (const entry of value.manifest.files) {
      const path = join(payload, entry.path)
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, readFileSync(join(value.output, entry.path)), { mode: Number.parseInt(entry.mode, 8) })
    }
    const manifest = createNativeNodeManifest(payload, value.manifest)
    const raw = Buffer.from(JSON.stringify(manifest, null, 2) + '\n')
    const signaturePath = join(build, 'signature'), publicKeyPath = join(build, 'key.pem')
    writeFileSync(join(build, 'release.manifest.json'), raw, { mode: 0o444 })
    writeFileSync(signaturePath, sign(null, Buffer.concat([Buffer.from(domain), raw]), privateKey).toString('base64') + '\n')
    writeFileSync(publicKeyPath, publicKey.export({ type: 'spki', format: 'pem' }))
    const result = finalizeNativeNodePackage({ buildDir: build, signaturePath, publicKeyPath })
    copyFileSync(join(build, 'cdnca-edge-agent.tar.gz'), join(build, 'package.tar.gz'))
    copyFileSync(join(value.root, 'trust.json'), join(build, 'trust.json'))
    const consumed = verify({ root: build, output: join(build, 'unpacked') })
    assert.equal(consumed.status, 0, consumed.stderr)
    assert.equal(JSON.parse(consumed.stdout).manifest_sha256, result.manifest_sha256)
    assert.equal(hash(readFileSync(join(build, 'package.tar.gz'))), result.sha256)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

const workerRecord = 'cdnca-runtime:x:995:995:CDNCA worker:/nonexistent:/usr/sbin/nologin\n'
const workerGroup = 'cdnca-runtime:x:995:\n'
const workerSudoDenial = 'User cdnca-runtime is not allowed to run sudo on fixture-node.\n'
for (const [name, options] of [
  ['new account', { create: true }],
  ['existing private system account', {}],
  ['Ubuntu sudo denial with exit 0', { sudoStatus: 0 }],
  ['sudo denial with exit 1', { sudoStatus: 1 }],
  ['sudo not installed', { sudoAbsent: true }],
  ['root UID', { record: workerRecord.replace(':995:995:', ':0:995:'), reject: true }],
  ['root GID', { record: workerRecord.replace(':995:995:', ':995:0:'), group: workerGroup.replace(':995:', ':0:'), reject: true }],
  ['interactive shell', { record: workerRecord.replace('/usr/sbin/nologin', '/bin/bash'), reject: true }],
  ['real home directory', { record: workerRecord.replace('/nonexistent', '/home/worker'), reject: true }],
  ['RHEL locked password status LK', { lock: 'LK' }],
  ['unlocked password', { lock: 'P', reject: true }],
  ['RHEL empty password status NP', { lock: 'NP', reject: true }],
  ['non-system UID', { record: workerRecord.replace(':995:995:', ':1500:995:'), reject: true }],
  ['supplementary privileged group', { groups: '995 27', reject: true }],
  ['primary group mismatch', { record: workerRecord.replace(':995:995:', ':995:996:'), reject: true }],
  ['shared group members', { group: workerGroup.replace(':995:', ':995:other'), reject: true }],
  ['shared UID', { extraRecord: 'other:x:995:994::/nonexistent:/usr/sbin/nologin\n', reject: true }],
  ['shared primary GID', { extraRecord: 'other:x:994:995::/nonexistent:/usr/sbin/nologin\n', reject: true }],
  ['shared numeric GID', { extraGroup: 'other:x:995:\n', reject: true }],
  ['sudo grant', { sudoOutput: 'User cdnca-runtime may run the following commands on fixture-node:\n    (ALL) ALL\n', reject: true }],
  ['restricted sudo grant', { sudoOutput: 'User cdnca-runtime may run the following commands on fixture-node:\n    (root) /usr/bin/journalctl\n', reject: true }],
  ['empty failed sudo query', { sudoOutput: '', sudoStatus: 1, reject: true }],
  ['empty successful sudo query', { sudoOutput: '', reject: true }],
  ['failed sudo query', { sudoOutput: 'sudo: unable to initialize policy plugin\n', sudoStatus: 1, reject: true }],
  ['unknown sudo output', { sudoOutput: 'Permission denied\n', sudoStatus: 1, reject: true }],
  ['sudo denial with diagnostic', { sudoStderr: 'sudo: unable to resolve host\n', reject: true }],
  ['sudo denial with unsupported status', { sudoStatus: 2, reject: true }],
  ['sudo query timeout', { sudoTimeout: true, reject: true }],
  ['sudo denial for another user', { sudoOutput: workerSudoDenial.replace('cdnca-runtime', 'other'), reject: true }],
  ['sudo denial for another host', { sudoOutput: workerSudoDenial.replace('fixture-node', 'other-host'), reject: true }],
  ['sudo denial followed by another line', { sudoOutput: workerSudoDenial + '\n', reject: true }],
  ['oversized sudo output', { sudoOutput: workerSudoDenial + 'x'.repeat(10000), reject: true }],
  ['partial existing group', { record: '', reject: true }],
  ['failed account lookup', { lookupFailed: true, reject: true }],
]) {
  test(`native worker account ${options.reject ? 'rejects' : 'accepts'} ${name} without mutating existing identities`, () => {
    const value = shellFixture()
    try {
      const beforePasswd = options.create ? '' : (options.record ?? workerRecord) + (options.extraRecord ?? '')
      const beforeGroup = options.create ? '' : (options.group ?? workerGroup) + (options.extraGroup ?? '')
      value.file('accounts/passwd', beforePasswd)
      value.file('accounts/group', beforeGroup)
      const result = value.run(`
account_fixture="$1/accounts"
getent() {
  ${options.lookupFailed ? 'return 1' : ':'}
  if [[ "$#" == 1 ]]; then command cat "$account_fixture/$1"; return; fi
  awk -F: -v name="$2" '$1 == name {print; found=1} END {if (!found) exit 2}' "$account_fixture/$1"
}
groupadd() {
  [[ "$*" == '--system cdnca-runtime' ]] || return 92
  printf '%s\\n' 'cdnca-runtime:x:995:' >"$account_fixture/group"
  printf 'groupadd\\n' >>"$account_fixture/changes"
}
useradd() {
  [[ "$*" == '--system --gid cdnca-runtime --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin cdnca-runtime' ]] || return 93
  printf '%s\\n' 'cdnca-runtime:x:995:995:CDNCA worker:/nonexistent:/usr/sbin/nologin' >"$account_fixture/passwd"
  printf 'useradd\\n' >>"$account_fixture/changes"
}
id() {
  case "$1" in
    -u) printf 995 ;;
    -g) printf 995 ;;
    -G) printf '%s' '${options.groups ?? '995'}' ;;
    *) return 94 ;;
  esac
}
passwd() { printf '%s\\n' 'cdnca-runtime ${options.lock ?? 'L'} 2026-10-08 0 99999 7 -1'; }
hostname() { [[ "$*" == -s ]] || return 96; printf fixture-node; }
${options.sudoAbsent ? 'command() { if [[ "$*" == "-v sudo" ]]; then return 1; else builtin command "$@"; fi; }' : ''}
timeout() {
  [[ "$*" == '--kill-after=2s 10s sudo -n -l -U cdnca-runtime' && "$LC_ALL" == C ]] || return 97
  ${options.sudoTimeout ? 'return 124' : 'shift 2; "$@"'}
}
sudo() {
  [[ "$*" == '-n -l -U cdnca-runtime' ]] || return 98
  printf called >"$account_fixture/sudo-called"
  printf '%s' "$FIXTURE_SUDO_OUTPUT"
  printf '%s' "$FIXTURE_SUDO_STDERR" >&2
  return "$FIXTURE_SUDO_STATUS"
}
prepare_native_worker_account
printf verified >"$account_fixture/verified"
`, { FIXTURE_SUDO_OUTPUT: options.sudoOutput ?? workerSudoDenial, FIXTURE_SUDO_STDERR: options.sudoStderr ?? '', FIXTURE_SUDO_STATUS: String(options.sudoStatus ?? 0) })
      assert.equal(result.status === 0, !options.reject, result.stderr)
      assert.equal(existsSync(join(value.root, 'accounts/verified')), !options.reject)
      if (options.sudoAbsent || options.sudoTimeout) assert.equal(existsSync(join(value.root, 'accounts/sudo-called')), false)
      if (options.reject) assert.match(result.stderr, /native worker account rejected/)
      if (options.create) {
        assert.equal(readFileSync(join(value.root, 'accounts/changes'), 'utf8'), 'groupadd\nuseradd\n')
        assert.equal(readFileSync(join(value.root, 'accounts/passwd'), 'utf8'), workerRecord)
      } else {
        assert.equal(existsSync(join(value.root, 'accounts/changes')), false)
        assert.equal(readFileSync(join(value.root, 'accounts/passwd'), 'utf8'), beforePasswd)
        assert.equal(readFileSync(join(value.root, 'accounts/group'), 'utf8'), beforeGroup)
      }
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('native preflight and package activation precede enrollment; no configuration current is created', () => {
  const main = script.match(/main\(\) \{([\s\S]+?)\n\}/)?.[1] ?? ''
  for (const required of ['assert_blank_host', 'install_trust_material', 'download_agent', 'preflight_native_runtime', 'activate_native_package', 'enroll']) assert.ok(main.includes(required), required)
  assert.ok(main.indexOf('install_trust_material') < main.indexOf('download_agent'))
  assert.ok(main.indexOf('preflight_native_runtime') < main.search(/\n +enroll\n/))
  assert.ok(main.includes('prepare_native_worker_account'))
  assert.ok(main.indexOf('preflight_native_runtime') < main.indexOf('prepare_native_worker_account'))
  assert.ok(main.indexOf('prepare_native_worker_account') < main.indexOf('activate_native_package'))
  assert.ok(main.indexOf('activate_native_package') < main.search(/\n +enroll\n/))
  assert.equal(/ln .*STATE_ROOT|ln .*site-runtime/.test(script), false)
  assert.ok(script.includes("systemd_service: \"cdnca-openresty-native.service\""))
  // The Agent runs the packaged probe by absolute path, through the stable current link.
  assert.ok(script.includes('http3_probe: "/opt/cdnca-node/current/runtime/bin/h3probe"'))
})

// Upgrade trust: the copied command pins cdnca.edge-upgrade-trust/v1 by SHA-256;
// any missing, mismatched or malformed document stops the install closed.
function upgradeTrustDocument(overrides = {}) {
  const pem = () => generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' })
  return { schema: 'cdnca.edge-upgrade-trust/v1', installation_id: '00000000-0000-4000-8000-0000000000aa',
    control_execution: { version: 1, keys: [{ key_id: 'control-execution-v1', public_key_pem: pem() }] },
    edge_execution: { version: 1, keys: [{ key_id: 'edge-execution-v1', public_key_pem: pem() }] },
    download: { host: 'auth.example.test', port: 443, addresses: ['203.0.113.7', '2001:db8::7'], root_ca: 'system' },
    artifact_trust: { version: 1, keys: [{ key_id: 'release', public_key_pem: pem() },
      { key_id: 'native-edge-00000000-0000-4000-8000-0000000000aa-v1', public_key_pem: pem() }] }, ...overrides }
}

test('node installer requires a well-formed upgrade trust pin before any download', () => {
  const rootless = script.replace(`[ "$EUID" -eq 0 ] || fail 'run this installer as root'`, ':')
  assert.notEqual(rootless, script)
  for (const [flags, message] of [['', /--upgrade-trust-sha256 is required; copy a new install command/], ['--upgrade-trust-sha256 abc', /exactly 64 hexadecimal/]]) {
    const result = spawnSync('bash', ['-c', `${rootless}\nparse_args --control-plane https://control.example --enrollment-token fixture-token ${flags}\nnormalise_defaults`], { encoding: 'utf8' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, message)
  }
  const pinned = spawnSync('bash', ['-c', `${rootless}\nparse_args --control-plane https://control.example --enrollment-token fixture-token --upgrade-trust-sha256 ${'AB'.repeat(32)}\nnormalise_defaults\nprintf '%s %s' "$UPGRADE_TRUST_SHA256" "$UPGRADE_TRUST_URL"`], { encoding: 'utf8' })
  assert.equal(pinned.status, 0, pinned.stderr)
  assert.equal(pinned.stdout, `${'ab'.repeat(32)} https://control.example/downloads/edge-agent/upgrade-trust.json`)
})

const signerTrustRoot = { key_id: 'cdnca-offline-root', generation: 1, public_key: 'A'.repeat(42) + 'E' }
for (const [name, mutate, pinMatches] of [
  ['valid document', (value) => value, true],
  ['valid document with the offline root pin', (value) => ({ ...value, signer_trust_root: signerTrustRoot }), true],
  ['malformed offline root pin', (value) => ({ ...value, signer_trust_root: { ...signerTrustRoot, generation: 0 } }), true],
  ['offline root pin with an extra field', (value) => ({ ...value, signer_trust_root: { ...signerTrustRoot, private_key: 'x' } }), true],
  ['digest mismatch', (value) => value, false],
  ['shared control and edge key', (value) => ({ ...value, edge_execution: value.control_execution }), true],
  ['malformed private download root', (value) => ({ ...value, download: { ...value.download, root_ca: 'pinned' } }), true],
  ['IP download host with other addresses', (value) => ({ ...value, download: { ...value.download, host: '203.0.113.7' } }), true],
  ['noncanonical IPv6 download host', (value) => ({ ...value, download: { ...value.download, host: '2001:DB8::7', addresses: ['2001:db8::7'] } }), true],
  ['duplicate mapped address', (value) => ({ ...value, download: { ...value.download, addresses: ['203.0.113.7', '::ffff:203.0.113.7'] } }), true],
  ['unknown field', (value) => ({ ...value, extra: true }), true],
  // fix-r1c: 1.0.35 fresh installs always carry the artifact key pin.
  ['missing artifact key pin', ({ artifact_trust: _, ...value }) => value, true],
  ['empty artifact key pin', (value) => ({ ...value, artifact_trust: { version: 1, keys: [] } }), true],
  ['artifact key pin with a private field', (value) => ({ ...value, artifact_trust: { version: 1,
    keys: [{ ...value.artifact_trust.keys[0], private_key_pem: 'x' }] } }), true],
  ['artifact key pin with a duplicate key ID', (value) => ({ ...value, artifact_trust: { version: 1,
    keys: [value.artifact_trust.keys[0], value.artifact_trust.keys[0]] } }), true],
]) {
  test(`upgrade trust installation fails closed or splits exact stores (${name})`, () => {
    const value = shellFixture()
    try {
      const body = JSON.stringify(mutate(upgradeTrustDocument()))
      const served = value.file('served.json', body)
      const digest = createHash('sha256').update(pinMatches ? body : `${body} `).digest('hex')
      const result = value.run(`
TEMP_DIR="$1/temporary"; mkdir -m 0700 "$TEMP_DIR"
curl_download() { while [[ "$1" != --output ]]; do shift; done; cp "$FIXTURE_SERVED" "$2"; }
select_download_root() { printf 'root\\n' >"$4"; printf '%s %s %s' "$1" "$2" "$3" >"$FIXTURE_ROOT/root-args"; }
UPGRADE_TRUST_URL=https://control.example/downloads/edge-agent/upgrade-trust.json
UPGRADE_TRUST_FALLBACK_URL=$UPGRADE_TRUST_URL
UPGRADE_TRUST_SHA256=${digest}
install_upgrade_trust
cp -Rp "$TEMP_DIR/upgrade-trust" "$1/installed-trust"
printf '%s|%s|%s|%s|%s|%s' "$UPGRADE_INSTALLATION_ID" "$UPGRADE_DOWNLOAD_HOST" "$UPGRADE_DOWNLOAD_PORT" "$UPGRADE_DOWNLOAD_ADDRESSES" "$SIGNER_TRUST_ROOT" "\${ARTIFACT_TRUST_PIN#"$TEMP_DIR"/}"
`, { FIXTURE_SERVED: served, FIXTURE_ROOT: value.root })
      const valid = name.startsWith('valid document')
      assert.equal(result.status === 0, valid, result.stderr)
      if (!valid) {
        assert.match(result.stderr, name === 'digest mismatch' ? /does not match --upgrade-trust-sha256/ : /node upgrade trust document is invalid/)
        assert.equal(existsSync(join(value.root, 'root-args')), false)
        return
      }
      const pin = name.endsWith('pin') ? JSON.stringify(signerTrustRoot) : ''
      assert.equal(result.stdout.split('\n').at(-1), `00000000-0000-4000-8000-0000000000aa|auth.example.test|443|["203.0.113.7","2001:db8::7"]|${pin}|upgrade-trust/artifact-trust.json`)
      assert.equal(readFileSync(join(value.root, 'root-args'), 'utf8'), 'auth.example.test 443 ["203.0.113.7","2001:db8::7"]')
      const document = JSON.parse(body)
      for (const [file, expected] of [['control-execution.json', document.control_execution], ['edge-execution.json', document.edge_execution],
        ['artifact-trust.json', document.artifact_trust]]) {
        const path = join(value.root, 'installed-trust', file)
        assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), expected)
        assert.equal(statSync(path).mode & 0o777, 0o400)
      }
      assert.equal(statSync(join(value.root, 'installed-trust/download-ca.pem')).mode & 0o777, 0o400)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

// IP literal control plane: the trust document embeds the private root CA,
// which is installed as-is (no system-root probing of the live endpoint).
test('upgrade trust with an IP literal control plane installs the embedded private root', () => {
  const value = shellFixture()
  try {
    const made = spawnSync('bash', ['-c', `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=root \\
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$1/root.key" -out "$1/root.pem" 2>/dev/null`, 'x', value.root], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    const rootPem = readFileSync(join(value.root, 'root.pem'), 'utf8')
    const body = JSON.stringify(upgradeTrustDocument({ download: { host: '203.0.113.9', port: 8443, addresses: ['203.0.113.9'], root_ca: rootPem } }))
    const served = value.file('served.json', body)
    const digest = createHash('sha256').update(body).digest('hex')
    const result = value.run(`
TEMP_DIR="$1/temporary"; mkdir -m 0700 "$TEMP_DIR"
curl_download() { while [[ "$1" != --output ]]; do shift; done; cp "$FIXTURE_SERVED" "$2"; }
select_download_root() { exit 75; }
UPGRADE_TRUST_URL=https://203.0.113.9:8443/downloads/edge-agent/upgrade-trust.json
UPGRADE_TRUST_FALLBACK_URL=$UPGRADE_TRUST_URL
UPGRADE_TRUST_SHA256=${digest}
install_upgrade_trust
cp -p "$TEMP_DIR/upgrade-trust/download-ca.pem" "$1/installed-ca.pem"
printf '%s|%s|%s' "$UPGRADE_DOWNLOAD_HOST" "$UPGRADE_DOWNLOAD_PORT" "$UPGRADE_DOWNLOAD_ADDRESSES"
`, { FIXTURE_SERVED: served })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.split('\n').at(-1), '203.0.113.9|8443|["203.0.113.9"]')
    assert.equal(readFileSync(join(value.root, 'installed-ca.pem'), 'utf8'), rootPem)
    assert.equal(statSync(join(value.root, 'installed-ca.pem')).mode & 0o777, 0o400)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('upgrade download root is the single system anchor that verifies the live endpoint', async () => {
  const value = shellFixture()
  const port = await new Promise((resolve) => { const server = createServer().listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)) }) })
  try {
    const result = value.run(`
set -euo pipefail
cd "$1"
for name in decoy root; do
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=$name" \\
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$name.key" -out "$name.pem" 2>/dev/null
done
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=auth.example.test -keyout leaf.key -out leaf.csr 2>/dev/null
printf 'subjectAltName=DNS:auth.example.test\\nextendedKeyUsage=serverAuth\\n' >leaf.ext
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 1 -extfile leaf.ext -out leaf.pem 2>/dev/null
mkdir -p etc/ssl/certs
cat decoy.pem root.pem >etc/ssl/certs/ca-certificates.crt
openssl s_server -quiet -accept ${port} -cert leaf.pem -key leaf.key -www </dev/null >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/${port}) 2>/dev/null && break; sleep 0.1; done
select_download_root auth.example.test ${port} '["127.0.0.1"]' "$1/selected.pem"
cmp -s selected.pem root.pem
cat decoy.pem >etc/ssl/certs/ca-certificates.crt
if select_download_root auth.example.test ${port} '["127.0.0.1"]' "$1/unverified.pem" 2>"$1/unverified.err"; then exit 70; fi
[ ! -e unverified.pem ]
if select_download_root other.example.test ${port} '["127.0.0.1"]' "$1/wrong-name.pem" 2>/dev/null; then exit 71; fi
grep -Fq 'not verified by a system root' unverified.err
`)
    assert.equal(result.status, 0, result.stderr)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

// The installer raises the edge kernel baseline,
// never lowers a larger operator value, skips keys the kernel lacks, and
// persists only what it changed.
test('installer applies the kernel parameter baseline without lowering operator values', () => {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-sysctl-'))
  try {
    const proc = join(root, 'proc')
    const set = (name, value) => {
      const path = join(proc, ...name.split('.'))
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, `${value}\n`)
    }
    const get = (name) => readFileSync(join(proc, ...name.split('.')), 'utf8').trim()
    set('net.core.somaxconn', 4096)           // raised
    set('net.ipv4.tcp_fin_timeout', 60)       // lowered (max)
    set('net.ipv4.tcp_max_syn_backlog', 262144) // operator value above baseline: kept
    set('vm.max_map_count', 65530)            // raised
    // fix-cfl-b: PMTU black hole between node and control
    // plane stalls large config syncs; TCP MTU probing on black hole (1).
    set('net.ipv4.tcp_mtu_probing', 0)        // raised
    const conf = join(root, 'etc', 'sysctl.d', '90-cdnca-edge.conf')
    const env = { ...process.env, CDNCA_SYSCTL_ROOT: proc, CDNCA_SYSCTL_CONF: conf }
    const run = (extra = '') => spawnSync('bash', ['-c', `${script}\n${extra}\ntune_sysctl`], { encoding: 'utf8', env })
    const first = run()
    assert.equal(first.status, 0, first.stderr)
    assert.equal(get('net.core.somaxconn'), '65535')
    assert.equal(get('net.ipv4.tcp_fin_timeout'), '15')
    assert.equal(get('net.ipv4.tcp_max_syn_backlog'), '262144')
    assert.equal(get('vm.max_map_count'), '262144')
    assert.equal(get('net.ipv4.tcp_mtu_probing'), '1')
    const persisted = readFileSync(conf, 'utf8')
    assert.match(persisted, /^net\.core\.somaxconn = 65535$/m)
    assert.match(persisted, /^net\.ipv4\.tcp_fin_timeout = 15$/m)
    assert.match(persisted, /^net\.ipv4\.tcp_mtu_probing = 1$/m)
    assert.doesNotMatch(persisted, /tcp_max_syn_backlog/, 'unchanged keys are not pinned')
    assert.doesNotMatch(persisted, /fs\.file-max/, 'keys the kernel lacks are skipped')
    assert.match(first.stdout, /4 changed/)
    rmSync(conf)
    const second = run()
    assert.equal(second.status, 0, second.stderr)
    assert.match(second.stdout, /already meet the edge baseline/)
    assert.ok(!existsSync(conf), 'a host already at baseline gets no drop-in')
    set('net.core.somaxconn', 128)
    const skipped = run('SKIP_SYSCTL_TUNING=true')
    assert.equal(skipped.status, 0, skipped.stderr)
    assert.equal(get('net.core.somaxconn'), '128')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('installer runs kernel tuning after enrollment and before the service starts', () => {
  const main = script.slice(script.indexOf('\nmain() {'))
  assert.ok(main.indexOf('  enroll\n') < main.indexOf('  tune_sysctl\n'))
  assert.ok(main.indexOf('  tune_sysctl\n') < main.indexOf('  setup_service\n'))
  const help = spawnSync('bash', ['-c', `${script}\nusage`], { encoding: 'utf8' })
  assert.match(help.stdout, /--skip-sysctl-tuning/)
})
