import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { chmodSync, chownSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

const installer = new URL('../deploy/systemd/install-native-control-upgrade-runner.sh', import.meta.url)
const digest = (value) => createHash('sha256').update(value).digest('hex')
const installationID = '3d519c71-4bdb-4e61-82a8-5312c6b47f21'
const elf = Buffer.alloc(64)
Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf)
elf.writeUInt16LE(2, 16)
elf.writeUInt16LE(62, 18)

function runnerInstallerFixture(signed = false) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-native-runner-installer.')))
  const file = (path, body, mode = 0o600) => {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true, mode: 0o755 })
    writeFileSync(target, body, { mode })
    return target
  }
  const directory = (path, mode) => { mkdirSync(join(root, path), { recursive: true }); chmodSync(join(root, path), mode) }
  const archive = Buffer.from('fixture only: full signed archive verification belongs to the caller\n')
  const baselineSHA = digest(archive)
  const release = `data/cdnca-native-root/cdnca/releases/${baselineSHA}`
  file(`data/cdnca-native-root/cdnca/artifacts/${baselineSHA}.tar`, archive)
  const key = signed ? generateKeyPairSync('ed25519') : null
  const manifest = JSON.stringify(signed ? { schema: 'cdnca.native-management.release/v2', key_id: 'artifact-fixture' } : { schema: 'cdnca.native-management.release/v1' })
  file(`${release}/release.manifest.json`, manifest, 0o644)
  if (signed) {
    file(`${release}/release.manifest.sig`, sign(null, Buffer.from('cdnca.native-management.release/v2\n' + manifest), key.privateKey).toString('base64') + '\n', 0o644)
    file('var/lib/cdnca-upgrade/artifact-trust.json', JSON.stringify({ version: 1, keys: [{ key_id: 'artifact-fixture', public_key_pem: key.publicKey.export({ type: 'spki', format: 'pem' }) }] }))
  }
  file(`${release}/bin/control-api`, elf, 0o755)
  file(`${release}/bin/agent-gateway`, elf, 0o755)
  file(`${release}/static/web/index.html`, '<!doctype html>', 0o644)
  symlinkSync(join(root, release), join(root, 'data/cdnca-native-root/cdnca/current'))
  if (!signed) directory('var/lib/cdnca-upgrade/source.git', 0o700)
  directory('var/lib/cdnca-upgrade', 0o700)
  directory('var/lib/cdnca-native-upgrade-maintenance', 0o2750)
  directory('run/cdnca-upgrade', 0o2750)
  directory('run/lock', 0o1777)
  file('run/lock/cdnca-management-release.lock', '', 0o640)
  file('var/lib/cdnca-native-upgrade-maintenance/maintenance.json.lock', '', 0o640)
  file('var/lib/cdnca-native-upgrade-maintenance/maintenance.json', JSON.stringify({
    schema: 'cdnca.native-management.maintenance/v1', installation_id: installationID,
    phase: 'active', plan_id: '', observed_at: '2026-10-08T00:00:00Z',
  }), 0o640)
  file('etc/os-release', 'ID=ubuntu\nVERSION_ID="24.04"\n', 0o644)
  file('etc/cdnca-upgrade/installation-id', installationID + '\n')
  file('etc/cdnca-upgrade/trusted-keys.json', JSON.stringify({ keys: [{ key_id: 'fixture', public_key: Buffer.alloc(32, 7).toString('base64url') }] }))
  file('etc/cdnca-upgrade/plan-source-token', 'x'.repeat(48) + '\n')
  file('input/runner', elf, 0o755)
  directory('usr/local/libexec/cdnca', 0o755)
  directory('etc/systemd/system', 0o755)
  directory('etc/tmpfiles.d', 0o755)
  const openssl = spawnSync('which', ['openssl'], { encoding: 'utf8' }).stdout.trim()
  for (const [name, extension] of [['ca', 'basicConstraints=critical,CA:TRUE'], ['client', 'extendedKeyUsage=clientAuth']]) {
    const result = spawnSync(openssl, ['req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '2', '-subj', `/CN=fixture-${name}`,
      '-addext', extension, '-keyout', join(root, `etc/cdnca-upgrade/${name}-key.pem`), '-out', join(root, `etc/cdnca-upgrade/${name}.pem`)], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
    chmodSync(join(root, `etc/cdnca-upgrade/${name}-key.pem`), 0o600)
    chmodSync(join(root, `etc/cdnca-upgrade/${name}.pem`), 0o644)
  }
  const env = {
    CONTROL_UPGRADE_TARGET: 'native-standalone',
    CONTROL_UPGRADE_INSTALLATION_ID_FILE: '/etc/cdnca-upgrade/installation-id',
    CONTROL_UPGRADE_TRUST_FILE: '/etc/cdnca-upgrade/trusted-keys.json',
    CONTROL_UPGRADE_INTERNAL_TOKEN_FILE: '/etc/cdnca-upgrade/plan-source-token',
    CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE: '/etc/cdnca-upgrade/ca.pem',
    CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE: '/etc/cdnca-upgrade/client.pem',
    CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE: '/etc/cdnca-upgrade/client-key.pem',
    CONTROL_UPGRADE_PLAN_SOURCE_URL: 'https://runner.example.test/v1/internal/control-upgrade/plan',
    CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT: '10s', CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES: '1048576',
    CONTROL_UPGRADE_POLL_INTERVAL: '5s', CONTROL_UPGRADE_STEP_TIMEOUT: '3m', CONTROL_UPGRADE_HEALTH_TIMEOUT: '2m',
    CONTROL_UPGRADE_PROTOCOL_VERSION: '1', CONTROL_UPGRADE_ONESHOT: 'false',
    CONTROL_UPGRADE_STATE_DIR: '/var/lib/cdnca-upgrade',
    CONTROL_UPGRADE_PLAN_LKG_FILE: '/var/lib/cdnca-upgrade/last-known-plan.json',
    CONTROL_UPGRADE_RELEASE_ROOT: '/data/cdnca-native-root/cdnca',
    CDNCA_NATIVE_UPGRADE_STATUS_FILE: '/run/cdnca-upgrade/status.json',
    CDNCA_NATIVE_UPGRADE_MAINTENANCE_FILE: '/var/lib/cdnca-native-upgrade-maintenance/maintenance.json',
    CDNCA_NATIVE_UPGRADE_RELEASE_LOCK_FILE: '/run/lock/cdnca-management-release.lock',
    CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR: '/var/lib/cdnca-upgrade/source.git',
    CDNCA_NATIVE_UPGRADE_CONTROL_UNIT: 'cdnca-control-api.service',
    CDNCA_NATIVE_UPGRADE_GATEWAY_UNIT: 'cdnca-agent-gateway.service',
    CDNCA_NATIVE_UPGRADE_CONTROL_HEALTH_URL: 'http://127.0.0.1:8080/health/ready',
    CDNCA_NATIVE_UPGRADE_GATEWAY_HEALTH_URL: 'http://127.0.0.1:8082/health/ready',
    CDNCA_NATIVE_UPGRADE_WEB_INDEX_URL: 'https://control.example.test/dashboard/',
  }
  if (signed) {
    delete env.CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR
    env.CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE = '/var/lib/cdnca-upgrade/artifact-trust.json'
  }
  const systemctl = file('fixture-bin/systemctl', '#!/bin/sh\nprintf "%s\\n" "$*" >> "${FIXTURE_ROOT}/systemctl.log"\n[ "${FIXTURE_SYSTEMCTL_FAIL:-}" != "true" ]\n', 0o755)
  const checkBoot = () => {
    const unit = readFileSync(join(root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8')
    const command = unit.match(/^ExecStartPre=\/usr\/bin\/python3 -I -c "([^"\n]+)"$/m)
    assert.ok(command, 'the runner must validate volatile paths before executing')
    return spawnSync('python3', ['-I', '-c', command[1]], { encoding: 'utf8', timeout: 3000 })
  }
  return { root, file, env, baselineSHA, release, openssl, systemctl, checkBoot }
}

function runRunnerBootTmpfiles(value, boot = true) {
  const configuration = readFileSync(join(value.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf'), 'utf8')
    .replaceAll(value.root, '')
  return spawnSync('/usr/bin/systemd-tmpfiles', ['--root', value.root, '--create', ...(boot ? ['--boot'] : []), '-'], {
    input: configuration, encoding: 'utf8', timeout: 3000, env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
  })
}

function runRunnerInstaller(value, mode = '--check', options = {}) {
  // Only the ephemeral source copy has OS/uid/path substitutions. Production has no bypass switches.
  let source = readFileSync(installer, 'utf8')
    .replace('OWNER = 0', `OWNER = ${process.getuid()}`)
    .replace('platform.system() == "Linux" and platform.machine() == "x86_64"', 'True')
    .replace('while True:  # protected parent chain', `while cursor != ${JSON.stringify(value.root)}:  # fixture boundary`)
  source = source.replace(/\/(?:usr\/local|usr\/lib\/(?:systemd|tmpfiles\.d)|lib\/(?:systemd|tmpfiles\.d)|etc|data|var\/lib|run)(?=\/|["'])/g,
    (prefix) => join(value.root, prefix.slice(1)))
  source = source.replace('"openssl"', JSON.stringify(value.openssl)).replaceAll('["openssl",', `[${JSON.stringify(value.openssl)},`)
    .replaceAll('["systemctl",', `[${JSON.stringify(value.systemctl)},`)
    .replace('except Exception:', 'except Exception:\n    import traceback\n    traceback.print_exc()')
  if (options.raceUnit) source = source.replace('os.link(temporary, path)', 'if path == UNIT_PATH:\n            pathlib.Path(path).write_text("concurrent owner")\n        os.link(temporary, path)')
  if (options.raceTmpfiles) source = source.replace('os.link(temporary, path)', 'if path == TMPFILES_PATH:\n            pathlib.Path(path).write_text("concurrent boot policy")\n        os.link(temporary, path)')
  const environment = Object.entries(value.env).map(([key, original]) => `${key}=${original.startsWith('/') ? value.root + original : original}`).join('\n') + '\n' + (options.extraEnv ?? '')
  value.file('input/runner.env', environment)
  const args = [mode, '--binary', join(value.root, 'input/runner'), '--binary-sha256', options.binarySHA ?? digest(readFileSync(join(value.root, 'input/runner'))),
    '--environment', join(value.root, 'input/runner.env'), '--baseline-sha256', options.baselineSHA ?? value.baselineSHA]
  return spawnSync('bash', ['-c', source, 'fixture', ...args], { encoding: 'utf8', timeout: options.timeout ?? 15000,
    env: { ...process.env, FIXTURE_ROOT: value.root, FIXTURE_SYSTEMCTL_FAIL: options.systemctlFail ? 'true' : '' } })
}

test('native runner static check never executes the runner, mutates inputs, or claims live readiness', () => {
  const value = runnerInstallerFixture()
  try {
    const result = runRunnerInstaller(value)
    assert.equal(result.status, 0, result.stderr)
    const output = JSON.parse(result.stdout)
    assert.equal(output.status, 'static_preflight_passed')
    assert.deepEqual(output.remaining_verification, ['signed_artifact_provenance', 'complete_baseline', 'server_mtls', 'live_runner_probe'])
    assert.equal(existsSync(join(value.root, 'systemctl.log')), false)
    assert.equal(existsSync(join(value.root, 'run/cdnca-upgrade/status.json')), false)
    assert.equal(existsSync(join(value.root, 'usr/local/libexec/cdnca/native-control-upgrade-runner')), false)
    assert.equal(existsSync(join(value.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf')), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('v2 runner install validates signed provenance and protects independent trust without a Git directory', () => {
  const value = runnerInstallerFixture(true)
  try {
    const result = runRunnerInstaller(value, '--install')
    assert.equal(result.status, 0, result.stderr)
    assert.equal(existsSync(join(value.root, 'var/lib/cdnca-upgrade/source.git')), false)
    const unit = readFileSync(join(value.root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8')
    assert.match(unit, /ReadOnlyPaths=.*var\/lib\/cdnca-upgrade\/artifact-trust.json/)
    assert.doesNotMatch(unit, /source.git/)
    assert.equal(readFileSync(join(value.root, 'systemctl.log'), 'utf8'), 'daemon-reload\n')
  } finally { rmSync(value.root, { recursive: true }) }
})

for (const [name, mutate] of [
  ['missing trust', (f) => unlinkSync(join(f.root, 'var/lib/cdnca-upgrade/artifact-trust.json'))],
  ['untrusted path', (f) => { f.env.CDNCA_NATIVE_UPGRADE_ARTIFACT_TRUST_FILE = '/input/untrusted.json' }],
  ['unknown trust field', (f) => f.file('var/lib/cdnca-upgrade/artifact-trust.json', '{"version":1,"keys":[],"extra":true}')],
  ['missing signature', (f) => unlinkSync(join(f.root, f.release, 'release.manifest.sig'))],
  ['invalid signature', (f) => f.file(`${f.release}/release.manifest.sig`, Buffer.alloc(64).toString('base64'), 0o644)],
  ['schema downgrade', (f) => f.file(`${f.release}/release.manifest.json`, '{"schema":"cdnca.native-management.release/v1"}', 0o644)],
  ['mixed Git profile', (f) => { f.env.CDNCA_NATIVE_UPGRADE_SOURCE_GIT_DIR = '/var/lib/cdnca-upgrade/source.git' }],
]) test(`v2 runner rejects ${name} before installation`, () => {
  const value = runnerInstallerFixture(true)
  try {
    mutate(value)
    assert.equal(runRunnerInstaller(value, '--install').status, 1)
    assert.equal(existsSync(join(value.root, 'usr/local/libexec/cdnca/native-control-upgrade-runner')), false)
    assert.equal(existsSync(join(value.root, 'systemctl.log')), false)
  } finally { rmSync(value.root, { recursive: true }) }
})

// 10-22 73: an operator certificate the system store cannot verify needs an
// explicit console-index CA; the key is optional, fixed-path and read-only.
function withWebCA(value, mode = 0o444) {
  const result = spawnSync(value.openssl, ['req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '2', '-subj', '/CN=control.example.test',
    '-keyout', join(value.root, 'input/web-key.pem'), '-out', join(value.root, 'input/web.pem')], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  value.file('etc/cdnca-upgrade/web-ca.pem', readFileSync(join(value.root, 'input/web.pem')), mode)
  chmodSync(join(value.root, 'etc/cdnca-upgrade/web-ca.pem'), mode)
  value.env.CDNCA_NATIVE_UPGRADE_WEB_CA_FILE = '/etc/cdnca-upgrade/web-ca.pem'
}

test('native runner accepts the optional read-only console web CA under the protected config directory', () => {
  const value = runnerInstallerFixture(true)
  try {
    withWebCA(value)
    const result = runRunnerInstaller(value, '--install')
    assert.equal(result.status, 0, result.stderr)
    const environment = readFileSync(join(value.root, 'etc/cdnca-upgrade/native-control-upgrade-runner.env'), 'utf8')
    assert.match(environment, /^CDNCA_NATIVE_UPGRADE_WEB_CA_FILE=.*\/etc\/cdnca-upgrade\/web-ca\.pem$/m)
    const unit = readFileSync(join(value.root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8')
    assert.match(unit, new RegExp(`^ReadOnlyPaths=${join(value.root, 'etc/cdnca-upgrade')} `, 'm'))
  } finally { rmSync(value.root, { recursive: true }) }
})

for (const [name, mutate] of [
  ['other path', (f) => { withWebCA(f); f.file('input/web-ca.pem', readFileSync(join(f.root, 'input/web.pem')), 0o444); f.env.CDNCA_NATIVE_UPGRADE_WEB_CA_FILE = '/input/web-ca.pem' }],
  ['writable mode', (f) => withWebCA(f, 0o644)],
  ['missing file', (f) => { withWebCA(f); unlinkSync(join(f.root, 'etc/cdnca-upgrade/web-ca.pem')) }],
  ['not a certificate', (f) => { withWebCA(f); chmodSync(join(f.root, 'etc/cdnca-upgrade/web-ca.pem'), 0o600); f.file('etc/cdnca-upgrade/web-ca.pem', 'not a certificate\n', 0o444); chmodSync(join(f.root, 'etc/cdnca-upgrade/web-ca.pem'), 0o444) }],
  ['private key appended', (f) => { withWebCA(f); const path = join(f.root, 'etc/cdnca-upgrade/web-ca.pem'); chmodSync(path, 0o600); writeFileSync(path, Buffer.concat([readFileSync(path), readFileSync(join(f.root, 'input/web-key.pem'))])); chmodSync(path, 0o444) }],
]) test(`native runner rejects web CA ${name} before installation`, () => {
  const value = runnerInstallerFixture(true)
  try {
    mutate(value)
    assert.equal(runRunnerInstaller(value, '--install').status, 1)
    assert.equal(existsSync(join(value.root, 'usr/local/libexec/cdnca/native-control-upgrade-runner')), false)
  } finally { rmSync(value.root, { recursive: true }) }
})

test('native runner install writes the dedicated unit and binary but never enables or starts it', () => {
  const value = runnerInstallerFixture()
  try {
    const result = runRunnerInstaller(value, '--install')
    assert.equal(result.status, 0, result.stderr)
    assert.equal(JSON.parse(result.stdout).status, 'installed_not_started')
    assert.equal(readFileSync(join(value.root, 'systemctl.log'), 'utf8'), 'daemon-reload\n')
    const binary = join(value.root, 'usr/local/libexec/cdnca/native-control-upgrade-runner')
    assert.deepEqual(readFileSync(binary), elf)
    assert.equal(lstatSync(binary).mode & 0o777, 0o755)
    assert.equal(lstatSync(join(value.root, 'etc/cdnca-upgrade/native-control-upgrade-runner.env')).mode & 0o777, 0o600)
    const unit = readFileSync(join(value.root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8')
    assert.match(unit, /User=root\n/)
    assert.match(unit, /RuntimeDirectory=cdnca-upgrade\nRuntimeDirectoryMode=2750\nRuntimeDirectoryPreserve=yes/)
    assert.match(unit, new RegExp(`Group=${process.getgid()}\\n`))
    assert.match(unit, /^Group=[0-9]+$/m)
    assert.match(unit, /ProtectSystem=strict/)
    assert.match(unit, /ProcSubset=all/)
    assert.doesNotMatch(unit, /ProcSubset=pid|--check|ExecStartPost/)
    assert.match(unit, /ReadWritePaths=.*data\/cdnca-native-root\/cdnca .*var\/lib\/cdnca-upgrade .*run\/cdnca-upgrade .*var\/lib\/cdnca-native-upgrade-maintenance .*run\/lock\/cdnca-management-release.lock/)
    assert.match(unit, /ReadOnlyPaths=.*var\/lib\/cdnca-upgrade\/source.git/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('native runner installs create-only boot rules for the exact baseline volatile paths', () => {
  const value = runnerInstallerFixture()
  try {
    const lock = join(value.root, 'run/lock/cdnca-management-release.lock')
    value.file('run/lock/cdnca-management-release.lock', 'existing locked inode', 0o640)
    const before = lstatSync(lock)
    const result = runRunnerInstaller(value, '--install')
    assert.equal(result.status, 0, result.stderr)
    const configuration = join(value.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf')
    assert.equal(readFileSync(configuration, 'utf8'),
      `# Create only at boot; never replace, truncate, or repair an existing inode.\n` +
      `d! ${value.root}/run/cdnca-upgrade :2750 :${process.getuid()} :${process.getgid()} - -\n` +
      `f! ${value.root}/run/lock/cdnca-management-release.lock :0600 :${process.getuid()} :${process.getgid()} - -\n`)
    assert.equal(lstatSync(configuration).mode & 0o777, 0o644)
    assert.equal(lstatSync(configuration).nlink, 1)
    assert.equal(lstatSync(lock).ino, before.ino)
    assert.equal(lstatSync(lock).mode, before.mode)
    assert.equal(readFileSync(lock, 'utf8'), 'existing locked inode')
    const unit = readFileSync(join(value.root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8')
    assert.match(unit, /^After=.*systemd-tmpfiles-setup\.service.*$/m)
    assert.match(unit, /^Requires=systemd-tmpfiles-setup\.service$/m)
    assert.equal(value.checkBoot().status, 0)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

for (const [name, change] of [
  ['missing lock', (f) => unlinkSync(join(f.root, 'run/lock/cdnca-management-release.lock'))],
  ['missing status directory', (f) => rmSync(join(f.root, 'run/cdnca-upgrade'), { recursive: true })],
  ['permissive lock', (f) => chmodSync(join(f.root, 'run/lock/cdnca-management-release.lock'), 0o644)],
  ['hard-linked lock', (f) => linkSync(join(f.root, 'run/lock/cdnca-management-release.lock'), join(f.root, 'lock-alias'))],
  ['symbolic lock', (f) => { unlinkSync(join(f.root, 'run/lock/cdnca-management-release.lock')); symlinkSync('target', join(f.root, 'run/lock/cdnca-management-release.lock')); f.file('run/lock/target', 'preserved', 0o644) }],
  ['symbolic status directory', (f) => { rmSync(join(f.root, 'run/cdnca-upgrade'), { recursive: true }); symlinkSync('../var/lib/cdnca-native-upgrade-maintenance', join(f.root, 'run/cdnca-upgrade')) }],
  ['permissive status directory', (f) => chmodSync(join(f.root, 'run/cdnca-upgrade'), 0o2777)],
  ['status missing setgid', (f) => chmodSync(join(f.root, 'run/cdnca-upgrade'), 0o750)],
  ...['run/lock/cdnca-management-release.lock', 'run/cdnca-upgrade'].map((path) => [`wrong group ${path}`, (f) => {
    const other = process.getuid() === 0 ? 65534 : process.getgroups().find((group) => group !== process.getgid())
    assert.notEqual(other, undefined, 'fixture needs a second permitted group')
    chownSync(join(f.root, path), process.getuid(), other)
    chmodSync(join(f.root, path), path.endsWith('.lock') ? 0o640 : 0o2750)
  }]),
  ['directory as lock', (f) => { unlinkSync(join(f.root, 'run/lock/cdnca-management-release.lock')); mkdirSync(join(f.root, 'run/lock/cdnca-management-release.lock'), { mode: 0o600 }) }],
]) {
  test(`native runner boot check rejects ${name} without repairing state`, () => {
    const value = runnerInstallerFixture()
    try {
      const installed = runRunnerInstaller(value, '--install')
      assert.equal(installed.status, 0, installed.stderr)
      change(value)
      const maintenance = readFileSync(join(value.root, 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json'))
      assert.notEqual(value.checkBoot().status, 0)
      assert.deepEqual(readFileSync(join(value.root, 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json')), maintenance)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('Linux root: actual tmpfiles recreates volatile paths after reboot without changing durable state or an existing lock',
  { skip: process.platform !== 'linux' || process.getuid() !== 0 }, () => {
    const value = runnerInstallerFixture()
    try {
      const installed = runRunnerInstaller(value, '--install')
      assert.equal(installed.status, 0, installed.stderr)
      const lock = join(value.root, 'run/lock/cdnca-management-release.lock')
      const status = join(value.root, 'run/cdnca-upgrade')
      const maintenance = readFileSync(join(value.root, 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json'))
      unlinkSync(lock)
      rmSync(status, { recursive: true })
      assert.notEqual(value.checkBoot().status, 0)
      const notBoot = runRunnerBootTmpfiles(value, false)
      assert.equal(notBoot.status, 0, notBoot.stderr)
      assert.equal(existsSync(lock), false)
      const boot = runRunnerBootTmpfiles(value)
      assert.equal(boot.status, 0, boot.stderr)
      assert.equal(lstatSync(lock).mode & 0o7777, 0o600)
      assert.equal(lstatSync(lock).uid, 0)
      assert.equal(lstatSync(status).mode & 0o7777, 0o2750)
      assert.equal(value.checkBoot().status, 0)
      value.file('run/lock/cdnca-management-release.lock', 'held inode')
      const before = lstatSync(lock)
      assert.equal(runRunnerBootTmpfiles(value).status, 0)
      assert.equal(lstatSync(lock).ino, before.ino)
      assert.equal(readFileSync(lock, 'utf8'), 'held inode')
      assert.deepEqual(readFileSync(join(value.root, 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json')), maintenance)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })

for (const kind of ['symlink', 'hardlink', 'wrong-mode']) {
  test(`Linux root: tmpfiles never repairs or changes a ${kind} lock and the boot check rejects it`,
    { skip: process.platform !== 'linux' || process.getuid() !== 0 }, () => {
      const value = runnerInstallerFixture()
      try {
        const installed = runRunnerInstaller(value, '--install')
        assert.equal(installed.status, 0, installed.stderr)
        const lock = join(value.root, 'run/lock/cdnca-management-release.lock')
        const target = value.file('run/lock/preserved-target', 'untouched', 0o644)
        unlinkSync(lock)
        if (kind === 'symlink') symlinkSync('preserved-target', lock)
        else if (kind === 'hardlink') linkSync(target, lock)
        else value.file('run/lock/cdnca-management-release.lock', 'untouched', 0o644)
        const before = lstatSync(target)
        const lockBefore = lstatSync(lock)
        const result = runRunnerBootTmpfiles(value)
        if (kind === 'symlink') assert.notEqual(result.status, 0)
        assert.equal(readFileSync(target, 'utf8'), 'untouched')
        assert.equal(lstatSync(target).ino, before.ino)
        assert.equal(lstatSync(target).mode, before.mode)
        assert.equal(lstatSync(lock).ino, lockBefore.ino)
        assert.equal(lstatSync(lock).mode, lockBefore.mode)
        assert.notEqual(value.checkBoot().status, 0)
      } finally { rmSync(value.root, { recursive: true, force: true }) }
    })
}

const rejected = [
  ['wrong runner hash', () => {}, { binarySHA: 'a'.repeat(64) }],
  ['wrong baseline hash', () => {}, { baselineSHA: 'b'.repeat(64) }],
  ['non-ELF runner', (f) => f.file('input/runner', '#!/bin/sh\nexit 0\n', 0o755)],
  ['wrong runner architecture', (f) => { const bad = Buffer.from(elf); bad.writeUInt16LE(183, 18); f.file('input/runner', bad, 0o755) }],
  ['HA environment pollution', (f) => { f.env.CONTROL_UPGRADE_EXPECTED_REPLICAS = '1' }],
  ['unknown environment key', (f) => { f.env.LD_PRELOAD = '/tmp/unsafe' }],
  ['wrong target', (f) => { f.env.CONTROL_UPGRADE_TARGET = 'systemd' }],
  ['duplicate environment key', () => {}, { extraEnv: 'CONTROL_UPGRADE_TARGET=native-standalone\n' }],
  ['plain HTTP plan source', (f) => { f.env.CONTROL_UPGRADE_PLAN_SOURCE_URL = 'http://runner.example.test/v1/internal/control-upgrade/plan' }],
  ...['10.0.0.1', '127.0.0.2', '0.0.0.0', '[::]', '[fd00::1]'].map((host) => [`forbidden literal plan source ${host}`, (f) => {
    f.env.CONTROL_UPGRADE_PLAN_SOURCE_URL = `https://${host}/v1/internal/control-upgrade/plan`
  }]),
  ['query on plan source', (f) => { f.env.CONTROL_UPGRADE_PLAN_SOURCE_URL += '?x=1' }],
  ['wrong fixed release root', (f) => { f.env.CONTROL_UPGRADE_RELEASE_ROOT = '/tmp/release' }],
  ['equal controlled units', (f) => { f.env.CDNCA_NATIVE_UPGRADE_GATEWAY_UNIT = f.env.CDNCA_NATIVE_UPGRADE_CONTROL_UNIT }],
  ['zero polling duration', (f) => { f.env.CONTROL_UPGRADE_POLL_INTERVAL = '0s' }],
  ['unbounded plan response', (f) => { f.env.CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES = '2147483648' }],
  ['oneshot mode', (f) => { f.env.CONTROL_UPGRADE_ONESHOT = 'true' }],
  ['weak token', (f) => f.file('etc/cdnca-upgrade/plan-source-token', 'short')],
  ['world-readable private key', (f) => chmodSync(join(f.root, 'etc/cdnca-upgrade/client-key.pem'), 0o644)],
  ['mismatched client key', (f) => f.file('etc/cdnca-upgrade/client-key.pem', readFileSync(join(f.root, 'etc/cdnca-upgrade/ca-key.pem')))],
  ['client certificate without clientAuth', (f) => f.file('etc/cdnca-upgrade/client.pem', readFileSync(join(f.root, 'etc/cdnca-upgrade/ca.pem')), 0o644)],
  ['empty trust keys', (f) => f.file('etc/cdnca-upgrade/trusted-keys.json', '{"keys":[]}')],
  ['duplicate trust JSON key', (f) => f.file('etc/cdnca-upgrade/trusted-keys.json', '{"keys":[],"keys":[]}')],
  ['maintenance drain', (f) => { const p = 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json'; const m = JSON.parse(readFileSync(join(f.root, p))); m.phase = 'draining'; f.file(p, JSON.stringify(m), 0o640) }],
  ['maintenance installation mismatch', (f) => { const p = 'var/lib/cdnca-native-upgrade-maintenance/maintenance.json'; const m = JSON.parse(readFileSync(join(f.root, p))); m.installation_id = 'different'; f.file(p, JSON.stringify(m), 0o640) }],
  ['permissive release lock', (f) => chmodSync(join(f.root, 'run/lock/cdnca-management-release.lock'), 0o644)],
  ['non-private runner state', (f) => chmodSync(join(f.root, 'var/lib/cdnca-upgrade'), 0o755)],
  ['non-setgid status directory', (f) => chmodSync(join(f.root, 'run/cdnca-upgrade'), 0o750)],
  ['different status and maintenance groups', (f) => {
    const other = process.getuid() === 0 ? 65534 : process.getgroups().find((group) => group !== process.getgid())
    assert.notEqual(other, undefined, 'fixture needs a second permitted group')
    chownSync(join(f.root, 'var/lib/cdnca-native-upgrade-maintenance'), process.getuid(), other)
    chmodSync(join(f.root, 'var/lib/cdnca-native-upgrade-maintenance'), 0o2750)
  }],
  ['replaceable credential parent', (f) => chmodSync(join(f.root, 'etc/cdnca-upgrade'), 0o777)],
  ['hard-linked trust', (f) => linkSync(join(f.root, 'etc/cdnca-upgrade/trusted-keys.json'), join(f.root, 'etc/cdnca-upgrade/trust-alias'))],
  ['wrong baseline ELF', (f) => f.file(`${f.release}/bin/control-api`, 'not an ELF', 0o755)],
  ['relative current symlink', (f) => { const p = join(f.root, 'data/cdnca-native-root/cdnca/current'); unlinkSync(p); symlinkSync(`releases/${f.baselineSHA}`, p) }],
  ['invalid unit name', (f) => { f.env.CDNCA_NATIVE_UPGRADE_CONTROL_UNIT = '-bad.service' }],
  ['missing archive', (f) => rmSync(join(f.root, `data/cdnca-native-root/cdnca/artifacts/${f.baselineSHA}.tar`))],
  ['linked trust input', (f) => { const p = join(f.root, 'etc/cdnca-upgrade/trusted-keys.json'); rmSync(p); symlinkSync('installation-id', p) }],
  ['existing native unit', (f) => f.file('etc/systemd/system/cdnca-native-control-upgrade-runner.service', 'preserve this unit', 0o644)],
  ['existing legacy unit', (f) => f.file('etc/systemd/system/cdnca-control-upgrade-runner.service', 'preserve HA', 0o644)],
  ['existing drop-in', (f) => f.file('etc/systemd/system/cdnca-native-control-upgrade-runner.service.d/override.conf', '[Service]\n', 0o644)],
  ['existing enablement link', (f) => {
    const p = join(f.root, 'etc/systemd/system/multi-user.target.wants')
    mkdirSync(p)
    symlinkSync('../cdnca-native-control-upgrade-runner.service', join(p, 'cdnca-native-control-upgrade-runner.service'))
  }],
  ['existing durable runner state', (f) => f.file('var/lib/cdnca-upgrade/state.json', '{}')],
  ['existing cached plan', (f) => f.file('var/lib/cdnca-upgrade/last-known-plan.json', '{}')],
  ['existing target binary', (f) => f.file('usr/local/libexec/cdnca/native-control-upgrade-runner', 'preserve binary', 0o755)],
  ['existing target environment', (f) => f.file('etc/cdnca-upgrade/native-control-upgrade-runner.env', 'preserve env')],
  ...['etc', 'run', 'usr/lib', 'lib'].map((prefix) => [`existing ${prefix} tmpfiles configuration`, (f) =>
    f.file(`${prefix}/tmpfiles.d/cdnca-native-control-upgrade-runner.conf`, 'preserve boot rules', 0o644)]),
  ['linked tmpfiles configuration', (f) => symlinkSync('/dev/null', join(f.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf'))],
  ['linked tmpfiles directory', (f) => { rmSync(join(f.root, 'etc/tmpfiles.d'), { recursive: true }); symlinkSync('systemd/system', join(f.root, 'etc/tmpfiles.d')) }],
]
for (const [name, change, options] of rejected) {
  test(`native runner static preflight rejects ${name} without publishing a unit`, () => {
    const value = runnerInstallerFixture()
    try {
      change(value)
      const before = readdirSync(join(value.root, 'etc/systemd/system')).sort()
      const result = runRunnerInstaller(value, '--install', options)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /native runner install rejected/)
      assert.equal(existsSync(join(value.root, 'systemctl.log')), false)
      assert.deepEqual(readdirSync(join(value.root, 'etc/systemd/system')).sort(), before)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('daemon-reload failure removes only this invocation newly created targets', () => {
  const value = runnerInstallerFixture()
  try {
    value.file('etc/cdnca-upgrade/keep', 'preserved')
    const result = runRunnerInstaller(value, '--install', { systemctlFail: true })
    assert.notEqual(result.status, 0)
    assert.equal(readFileSync(join(value.root, 'etc/cdnca-upgrade/keep'), 'utf8'), 'preserved')
    for (const path of ['etc/systemd/system/cdnca-native-control-upgrade-runner.service', 'etc/cdnca-upgrade/native-control-upgrade-runner.env', 'usr/local/libexec/cdnca/native-control-upgrade-runner', 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf']) {
      assert.equal(existsSync(join(value.root, path)), false)
    }
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('ordinary read access-time changes do not invalidate otherwise stable input files', () => {
  const value = runnerInstallerFixture()
  try {
    utimesSync(join(value.root, 'input/runner'), new Date('2020-01-01T00:00:00Z'), new Date('2020-01-01T00:00:00Z'))
    const result = runRunnerInstaller(value, '--check', { binarySHA: digest(elf) })
    assert.equal(result.status, 0, result.stderr)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('publication collision never overwrites the competing unit and rolls back owned files only', () => {
  const value = runnerInstallerFixture()
  try {
    const result = runRunnerInstaller(value, '--install', { raceUnit: true })
    assert.notEqual(result.status, 0)
    assert.equal(readFileSync(join(value.root, 'etc/systemd/system/cdnca-native-control-upgrade-runner.service'), 'utf8'), 'concurrent owner')
    assert.equal(existsSync(join(value.root, 'usr/local/libexec/cdnca/native-control-upgrade-runner')), false)
    assert.equal(existsSync(join(value.root, 'etc/cdnca-upgrade/native-control-upgrade-runner.env')), false)
    assert.equal(existsSync(join(value.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf')), false)
    assert.equal(existsSync(join(value.root, 'systemctl.log')), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('boot-policy publication collision preserves the competing file and removes only owned publications', () => {
  const value = runnerInstallerFixture()
  try {
    const result = runRunnerInstaller(value, '--install', { raceTmpfiles: true })
    assert.notEqual(result.status, 0)
    assert.equal(readFileSync(join(value.root, 'etc/tmpfiles.d/cdnca-native-control-upgrade-runner.conf'), 'utf8'), 'concurrent boot policy')
    for (const path of ['usr/local/libexec/cdnca/native-control-upgrade-runner', 'etc/cdnca-upgrade/native-control-upgrade-runner.env', 'etc/systemd/system/cdnca-native-control-upgrade-runner.service']) {
      assert.equal(existsSync(join(value.root, path)), false)
    }
    assert.equal(existsSync(join(value.root, 'systemctl.log')), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

for (const host of ['127.0.0.1', '[::1]']) {
  test(`native-only static preflight allows the explicit local mTLS endpoint ${host}`, () => {
    const value = runnerInstallerFixture()
    try {
      value.env.CONTROL_UPGRADE_PLAN_SOURCE_URL = `https://${host}:9443/v1/internal/control-upgrade/plan`
      const result = runRunnerInstaller(value)
      assert.equal(result.status, 0, result.stderr)
      assert.equal(JSON.parse(result.stdout).status, 'static_preflight_passed')
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  })
}

test('a FIFO input is rejected promptly without waiting for a writer', () => {
  const value = runnerInstallerFixture()
  try {
    const input = join(value.root, 'input/runner')
    unlinkSync(input)
    const made = spawnSync('mkfifo', ['-m', '700', input], { encoding: 'utf8' })
    assert.equal(made.status, 0, made.stderr)
    const result = runRunnerInstaller(value, '--check', { binarySHA: digest(elf), timeout: 1000 })
    assert.equal(result.signal, null)
    assert.equal(result.status, 1)
    assert.match(result.stderr, /native runner install rejected: runner_input/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})
