import assert from 'node:assert/strict'
import { chmodSync, linkSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function native_install_test_block(name) {
  const value = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0]
  assert.ok(value, `missing ${name}`)
  return value
}

test('one authenticated complete release replaces three independent latest downloads', () => {
  const main = native_install_test_block('main')
  assert.match(main, /download_native_support/)
  assert.doesNotMatch(main, /download_control_api|download_gateway|download_control_web/)
  const download = native_install_test_block('download_native_support')
  assert.match(download, /verify_native_install_package/)
  assert.match(download, /cdnca-control-native\.tar/)
  const baseline = native_install_test_block('prepare_native_baseline')
  assert.match(baseline, /bundle verify/)
  assert.match(baseline, /bundle unbundle/)
  assert.match(baseline, /--stage-directory/)
  assert.match(baseline, /--version/)
  assert.doesNotMatch(baseline, /git.*fetch|git.*clone/)
})

test('public installs require v2 while explicit private packages retain their v1 compatibility', () => {
  const download = native_install_test_block('download_native_support')
  assert.match(download, /required_schema=cdnca\.native-management\.install\/v2/)
  assert.match(download, /if \[ -n "\$CONTROL_NATIVE_FILE" \]/)
  assert.match(download, /required_schema=''/)
  assert.match(download, /verify_native_install_package.*"\$required_schema"/)
  assert.match(download, /NATIVE_ARTIFACT_TRUST_FILE=\$trust/)
  const setup = native_install_test_block('setup_native_upgrade')
  assert.match(setup, /baseline-input\/v2/)
  assert.match(setup, /install -m 0600 "\$NATIVE_ARTIFACT_TRUST_FILE" "\$\{RESPONSE_DIR\}\/native-artifact-trust\.json"/)
  assert.match(setup, /--artifact-trust-file "\$\{RESPONSE_DIR\}\/native-artifact-trust\.json"/)
})

test('fresh dependency and source verification precede identity writes and the community installation record', () => {
  const main = native_install_test_block('main')
  for (const step of ['configure_runtime_dependencies', 'prepare_native_baseline', 'preprovision_nats', 'configure_control_runtime', 'migrate_database']) {
    assert.ok(main.indexOf(step) > 0, step)
    assert.ok(main.indexOf(step) < main.indexOf('\n  install_community\n'), step)
  }
  assert.ok(main.indexOf('configure_runtime_dependencies') < main.indexOf('generate_identity'))
  // fix-r1c: upgrade-trust.json pins artifacts.json after the publisher key joined it.
  assert.ok(main.indexOf('\n  configure_control_runtime\n') < main.indexOf('\n  publish_upgrade_trust\n'))
  assert.ok(main.indexOf('\n  publish_upgrade_trust\n') < main.indexOf('\n  install_community\n'))
  assert.ok(main.indexOf('setup_native_upgrade') > main.indexOf('\n  install_community\n'))
  assert.ok(main.indexOf('verify_native_plan_source') > main.indexOf('setup_web'))
  assert.ok(main.indexOf('verify_native_plan_source') < main.indexOf('print_gateway_ports'))
  assert.doesNotMatch(main, /analytics storage disabled/)
})

test('fresh startup cannot reach Control before its real analytics generation bootstrap', () => {
  const main = native_install_test_block('main').replace('[ "$EUID" -eq 0 ]', 'true')
  const steps = main.split('\n').map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line))
  const stubs = [...new Set(['parse_args', 'valid_url', 'require_commands', ...steps])]
    .map((name) => `${name}() { :; }`)
  const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'fail() { exit 1; }; log() { :; }', ...stubs,
    'bootstrap_analytics_history() { initialized=true; }', 'setup_service() { [[ "$initialized" == true ]]; }',
    'gateway_mode_requested() { return 1; }', 'initialized=false', main, 'main'].join('\n')],
  { encoding: 'utf8', env: { ...process.env, SKIP_DEPENDENCIES: 'true', INSTALL_MODE: 'all', CONTROL_BINARY: '/opt/cdnca/current/bin/control-api' } })
  assert.equal(result.status, 0, 'fresh Control start must follow analytics bootstrap')
  assert.ok(main.indexOf('bootstrap_analytics_history') > main.indexOf('setup_native_upgrade'))
  assert.ok(main.indexOf('bootstrap_analytics_history') < main.indexOf('setup_service'))
})

test('an analytics bootstrap failure aborts before any service starts', () => {
  const main = native_install_test_block('main').replace('[ "$EUID" -eq 0 ]', 'true')
  const steps = main.split('\n').map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line))
  const stubs = [...new Set(['parse_args', 'valid_url', 'require_commands', ...steps])]
    .map((name) => `${name}() { :; }`)
  const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'fail() { exit 1; }; log() { :; }', ...stubs,
    'bootstrap_analytics_history() { return 1; }', 'setup_service() { printf unexpected-start; }',
    'gateway_mode_requested() { return 1; }', main, 'main'].join('\n')],
  { encoding: 'utf8', env: { ...process.env, SKIP_DEPENDENCIES: 'true', INSTALL_MODE: 'all', CONTROL_BINARY: '/opt/cdnca/current/bin/control-api' } })
  assert.equal(result.status, 1)
  assert.equal(result.stdout, '')
})

function analyticsBootstrapFixture(t, fault = '') {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-analytics-bootstrap-wiring.')))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const binary = join(directory, 'analytics-history-bootstrap'), manifest = join(directory, 'install.manifest.json')
  const lock = join(directory, 'release.lock'), receipt = join(directory, 'called.json')
  const elf = Buffer.alloc(80)
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(elf)
  elf.writeUInt16LE(2, 16); elf.writeUInt16LE(fault === 'architecture' ? 183 : 62, 18)
  writeFileSync(binary, elf, { mode: 0o755 })
  writeFileSync(manifest, JSON.stringify({ files: [{ path: 'analytics-history-bootstrap', bytes: elf.length,
    mode: 0o755, sha256: createHash('sha256').update(elf).digest('hex') }] }), { mode: 0o600 })
  writeFileSync(lock, '', { mode: 0o600 })
  const inode = statSync(lock).ino
  if (fault === 'mode') chmodSync(binary, 0o777)
  if (fault === 'hash') writeFileSync(binary, Buffer.alloc(80))
  if (fault === 'hardlink') linkSync(binary, join(directory, 'alias'))
  if (fault === 'symlink') { rmSync(binary); symlinkSync(manifest, binary) }
  if (fault === 'missing lock') rmSync(lock)
  if (fault === 'unsafe lock') chmodSync(lock, 0o644)
  const body = native_install_test_block('bootstrap_analytics_history')
    .match(/<<'PY_ANALYTICS_BOOTSTRAP'[^\n]*\n([\s\S]*?)\nPY_ANALYTICS_BOOTSTRAP/)[1]
    .replace('OWNER = 0', `OWNER = ${process.getuid()}`)
    .replace("Path('/run/lock/cdnca-management-release.lock')", `Path(${JSON.stringify(lock)})`)
    .replace('info.st_gid == 0', `info.st_gid == ${process.getgid()}`)
  const prefix = `import subprocess, json, sys\nfrom pathlib import Path
original_run = subprocess.run
def observed_run(arguments, **options):
    assert arguments == [${JSON.stringify(binary)}]
    assert set(options['env']) == {'DATABASE_URL','CONTROL_INSTALLATION_ID','ANALYTICS_INGEST_NATS_URL','PATH','LC_ALL'}
    assert options['env']['DATABASE_URL'] == 'postgresql://fixture:private-fixture-password@127.0.0.1/fixture'
    # A different process cannot take the same inode while the bootstrap is running.
    code = "import fcntl,os,sys\\nf=os.open(sys.argv[1],os.O_RDWR)\\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\\nexcept BlockingIOError: sys.exit(0)\\nsys.exit(1)"
    checked = original_run([sys.executable,'-I','-B','-c',code,${JSON.stringify(lock)}], capture_output=True)
    assert checked.returncode == 0
    Path(${JSON.stringify(receipt)}).write_text(json.dumps({'argv':arguments,'environment_names':sorted(options['env'])}))
    if ${JSON.stringify(fault)} == 'command failure': raise RuntimeError('injected failure')
subprocess.run = observed_run
`
  const result = spawnSync('python3', ['-I', '-B', '-', binary, manifest], { encoding: 'utf8', input: prefix + body, env: {
    ...process.env, DATABASE_URL: 'postgresql://fixture:private-fixture-password@127.0.0.1/fixture', CONTROL_INSTALLATION_ID: 'd583404d-4931-4fc3-94a1-28195c52b88c',
    ANALYTICS_INGEST_NATS_URL: fault === 'remote NATS' ? 'nats://192.0.2.1:4222' : 'nats://127.0.0.1:4222',
    PGPASSWORD: 'not-forwarded', ANALYTICS_INGEST_NATS_PASSWORD: 'not-forwarded',
  } })
  assert.doesNotMatch(result.stdout + result.stderr, /private-fixture-password|postgresql:\/\/|not-forwarded/)
  if (fault !== 'missing lock') assert.equal(statSync(lock).ino, inode)
  return { result, receipt }
}

test('bootstrap holds the original release lock and passes only protected env, never secret argv', (t) => {
  const { result, receipt } = analyticsBootstrapFixture(t)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(JSON.parse(readFileSync(receipt)).argv.length, 1)
})

for (const fault of ['mode', 'hash', 'architecture', 'hardlink', 'symlink', 'missing lock', 'unsafe lock', 'remote NATS', 'command failure']) {
  test(`analytics bootstrap rejects ${fault} without continuing startup`, (t) => {
    const { result } = analyticsBootstrapFixture(t, fault)
    assert.equal(result.status, 1, result.stderr)
    assert.match(result.stderr, /native analytics history bootstrap failed/)
  })
}

test('missing exact runtime function privileges abort bootstrap without granting permissions', () => {
  const block = native_install_test_block('bootstrap_analytics_history')
  const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'fail() { printf "%s\\n" "$1" >&2; exit 1; }',
    'control_database_psql() { [[ "$1" == analytics ]]; printf f; }', 'python3() { printf unexpected-execution; }', block,
    'bootstrap_analytics_history'].join('\n')], { encoding: 'utf8' })
  assert.equal(result.status, 1)
  assert.equal(result.stdout, '')
  assert.match(result.stderr, /function privileges are missing/)
  assert.doesNotMatch(block, /GRANT|REVOKE|UPDATE|DELETE|TRUNCATE/)
})

test('fixed NATS profile is checked and never updated in place', () => {
  const provision = native_install_test_block('preprovision_nats')
  assert.match(provision, /configure-nats\.py.*install/)
  assert.match(provision, /--receipt/)
  assert.doesNotMatch(provision, /stream update|consumer update/)
  // nats.json 自 918327477 起由 write_nats_config 生成（enable-gateway-access 复用），setup_nats 只调用它。
  const setup = native_install_test_block('setup_nats')
  assert.match(setup, /^  write_nats_config$/m)
  assert.match(setup, /127\.0\.0\.1:8222/)
  const config = native_install_test_block('write_nats_config')
  assert.match(config, /max_payload:4194304/)
  assert.match(config, /http:"127\.0\.0\.1:8222"/)
})

test('units use current binaries and verified runtime/native env; public nginx cannot reach private plan source', () => {
  const api = native_install_test_block('setup_service')
  assert.match(api, /EnvironmentFile=\$\{CONFIG_DIR\}\/runtime-extra\.env/)
  assert.match(api, /EnvironmentFile=\/etc\/cdnca-upgrade\/api\.env/)
  assert.match(api, /ExecStart=\$\{NATIVE_ROOT\}\/current\/bin\/control-api serve/)
  assert.match(native_install_test_block('setup_gateway'), /ExecStart=\$\{NATIVE_ROOT\}\/current\/bin\/agent-gateway/)
  for (const name of ['setup_service', 'setup_gateway']) {
    assert.match(native_install_test_block(name), /^CapabilityBoundingSet=$/m)
    assert.match(native_install_test_block(name), /^AmbientCapabilities=$/m)
  }
  assert.match(api, /After=.*systemd-tmpfiles-setup\.service/)
  assert.match(api, /^SupplementaryGroups=\$\(control_clamav_group\)$/m)
  const group = (id) => spawnSync('bash', ['-c', [native_install_test_block('control_os_family'), native_install_test_block('control_clamav_group'),
    `preflight_os_release_value() { printf ${id}; }`, 'control_clamav_group'].join('\n')], { encoding: 'utf8' }).stdout
  assert.equal(group('ubuntu'), 'clamav')
  assert.equal(group('debian'), 'clamav')
  assert.equal(group('rocky'), 'virusgroup')
  assert.match(source, /WEB_ROOT="\$\{NATIVE_ROOT\}\/current\/static\/web"/)
  const nginx = native_install_test_block('write_nginx_config')
  assert.match(nginx, /include \/etc\/cdnca-upgrade\/plan-source-nginx\.conf;/)
  assert.match(nginx, /location = \/v1\/internal \{ return 404; \}/)
  assert.match(nginx, /location \^~ \/v1\/internal\/ \{ return 404; \}/)
  assert.doesNotMatch(native_install_test_block('setup_web'), /curl -k|--insecure/)
})

test('native runner is installed without execution and only enabled after real mTLS checks', () => {
  const setup = native_install_test_block('setup_native_upgrade')
  assert.match(setup, /configure-native-upgrade\.py.*prepare/)
  assert.match(setup, /install-native-baseline\.py.*install/)
  assert.match(setup, /install-native-control-upgrade-runner\.sh.*--install/)
  assert.doesNotMatch(setup, /systemctl.*(start|enable)/)
  const preflight = native_install_test_block('verify_native_plan_source')
  assert.match(preflight, /--cacert/)
  assert.match(preflight, /--cert/)
  assert.match(preflight, /204/)
  assert.match(preflight, /401/)
  assert.match(preflight, /404/)
  assert.doesNotMatch(preflight, /--insecure|curl -k|Bearer \$\(/)
  assert.match(preflight, /systemctl enable --now.*native-control-upgrade-runner/)
  assert.match(preflight, /verify-native-upgrade/)
  for (const flag of ['installation-id', 'version', 'source-commit', 'source-tree', 'artifact-sha256', 'runner-sha256']) {
    assert.ok(preflight.includes(`--${flag}`), flag)
  }
  assert.match(preflight, /seq 1 30/)
})

test('dependency/readiness failure never writes the community installation record', () => {
  const main = native_install_test_block('main').replace('[ "$EUID" -eq 0 ]', 'true')
  const steps = main.split('\n').map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line))
  const expected = ['download_native_support', 'configure_runtime_dependencies', 'prepare_native_baseline', 'download_nats_binaries',
    'download_node_assets', 'prepare_database', 'migrate_database', 'setup_nats', 'preprovision_nats', 'configure_control_runtime',
    'publish_upgrade_trust']
  for (const failed of [...expected, '']) {
    for (const step of expected) assert.ok(steps.includes(step), step)
    const stubs = [...new Set(['parse_args', 'valid_url', 'require_commands', ...steps])]
      .map((name) => `${name}() { printf '%s\\n' '${name}'; [[ '${failed}' != '${name}' ]]; }`)
    // gateway_mode_requested must report "not gateway" (non-zero) to reach the fresh-install path (GW-10).
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'fail() { exit 1; }; log() { :; }', ...stubs,
      'gateway_mode_requested() { return 1; }', main, 'main'].join('\n')],
      { encoding: 'utf8', env: { ...process.env, SKIP_DEPENDENCIES: 'true', INSTALL_MODE: 'all', CONTROL_BINARY: '/opt/cdnca/current/bin/control-api' } })
    const calls = result.stdout.trim().split('\n')
    assert.equal(result.status === 0, failed === '', result.stderr)
    assert.equal(calls.filter((name) => name === 'install_community').length, failed ? 0 : 1)
  }
})
