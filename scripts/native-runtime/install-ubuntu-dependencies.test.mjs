import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

const execute = promisify(execFile)
const script = new URL('./install-ubuntu-dependencies.sh', import.meta.url).pathname
const packages = [
  'postgresql-17\tinstalled\t17.11-1.pgdg24.04+2',
  'postgresql-client-17\tinstalled\t17.11-1.pgdg24.04+2',
  ...['clickhouse-server', 'clickhouse-client', 'clickhouse-common-static'].map((name) => `${name}\tinstalled\t25.3.6.56`),
].join('\n')
const loopback = '<clickhouse>\n    <listen_host replace="replace">127.0.0.1</listen_host>\n    <interserver_listen_host replace="replace">127.0.0.1</interserver_listen_host>\n</clickhouse>\n'

function dependencyFixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-dependencies-test-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  chmodSync(root, 0o700)
  writeFileSync(join(root, 'os-release'), 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
  for (const path of ['clickhouse', 'clickhouse/config.d', 'clickhouse/users.d']) mkdirSync(join(root, path), { mode: 0o750 })
  for (const name of ['config.xml', 'users.xml']) writeFileSync(join(root, `clickhouse/${name}`), '<clickhouse/>', { mode: 0o640 })
  writeFileSync(join(root, 'clickhouse/config.d/cdnca-loopback.xml'), loopback, { mode: 0o644 })
  return root
}

async function runDependencyFunction(root, body, environment = {}) {
  try {
    const result = await execute('bash', ['-c', [
      'set -Eeuo pipefail', `source '${script}'`,
      'DEPS_PATH_BOUNDARY="$TEST_ROOT"', 'DEPS_ROOT_UID="$TEST_UID"',
      'DEPS_OS_RELEASE="$TEST_ROOT/os-release"', 'DEPS_LOOPBACK="$TEST_ROOT/clickhouse/config.d/cdnca-loopback.xml"',
      'DEPS_ADMIN_CONFIG="$TEST_ROOT/analytics/admin.xml"', 'DEPS_CLAM_SOCKET="$TEST_ROOT/clamd.ctl"',
      'DEPS_CLAM_DATABASE="$TEST_ROOT/clamdb"', 'DEPS_CLAM_CONFIG="$TEST_ROOT/clamd.conf"',
      'DEPS_CLAM_DROPIN="$TEST_ROOT/socket.d/cdnca-mode.conf"',
      'DEPS_CLAM_UNOWNED_OVERRIDES=("$TEST_ROOT/unowned-unit")',
      'DEPS_PG_VERSION=17.11-1.pgdg24.04+2 DEPS_PG_SUITE=noble-pgdg DEPS_OS_LABEL=ubuntu=24.04',
      'sleep() { :; }',
      body,
    ].join('\n')], { env: { ...process.env, TEST_ROOT: root, TEST_UID: String(process.getuid()), TEST_GID: String(process.getgid()), TEST_PACKAGES: packages, ...environment }, maxBuffer: 1024 * 1024 })
    return { status: 0, ...result }
  } catch (error) {
    return { status: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

test('profile accepts only root amd64 supported releases and does not source os-release', async (t) => {
  const root = dependencyFixture(t)
  const body = 'id() { printf 0; }; uname() { if [[ ${1-} == -s ]]; then printf Linux; else printf x86_64; fi; }; dpkg() { printf amd64; }; native_dependencies_profile'
  assert.equal((await runDependencyFunction(root, body)).status, 0)
  for (const [content, version, suite] of [
    ['ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', '17.11-1.pgdg24.04+2', 'noble-pgdg'],
    ['ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\n', '17.11-1.pgdg22.04+2', 'jammy-pgdg'],
    ['PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n', '17.11-1.pgdg12+2', 'bookworm-pgdg'],
    ['PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n', '17.11-1.pgdg13+2', 'trixie-pgdg'],
  ]) {
    writeFileSync(join(root, 'os-release'), content)
    const result = await runDependencyFunction(root, `${body}; printf '%s %s' "$DEPS_PG_VERSION" "$DEPS_PG_SUITE"`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, `${version} ${suite}`)
  }
  for (const [content, extra, code] of [
    ['ID=debian\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', '', 'unsupported_os'],
    ['ID=ubuntu\nVERSION_ID="16.04"\nVERSION_CODENAME=xenial\n', '', 'unsupported_os'],
    ['ID=ubuntu\nVERSION_ID="18.04"\nVERSION_CODENAME=bionic\n', '', 'unsupported_os'],
    ['ID=debian\nVERSION_ID="9"\nVERSION_CODENAME=stretch\n', '', 'unsupported_os'],
    ['ID=debian\nVERSION_ID="11"\nVERSION_CODENAME=buster\n', '', 'unsupported_os'],
    ['ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=trixie\n', '', 'unsupported_os'],
    ['ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', 'dpkg() { printf arm64; };', 'unsupported_architecture'],
    ['ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', 'id() { printf 501; };', 'root_required'],
    ['ID=ubuntu\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', '', 'unsupported_os'],
  ]) {
    writeFileSync(join(root, 'os-release'), content)
    const result = await runDependencyFunction(root, body.replace('native_dependencies_profile', `${extra} native_dependencies_profile`))
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, new RegExp(code))
  }
  writeFileSync(join(root, 'os-release'), `ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\ntouch '${root}/executed'\n`)
  assert.equal((await runDependencyFunction(root, body)).status, 0)
  assert.equal(existsSync(join(root, 'executed')), false)
})

test('package profile rejects partial, mismatched and additional PostgreSQL majors', async (t) => {
  const root = dependencyFixture(t)
  const body = 'dpkg-query() { printf "%s\\n" "$TEST_PACKAGES"; }; native_dependencies_packages'
  for (const [input, expected] of [[packages, 'installed'], ['', 'fresh']]) {
    const result = await runDependencyFunction(root, body, { TEST_PACKAGES: input })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), expected)
  }
  for (const input of [packages.replace('17.11-1.pgdg24.04+2', '17.10-1.pgdg24.04+1'), packages.replace('25.3.6.56', '25.3.7.1'), packages.split('\n').slice(1).join('\n'), `${packages}\npostgresql-16\tinstalled\t16.9`, `${packages}\npostgresql-client-18\tinstalled\t18.0`]) {
    const result = await runDependencyFunction(root, body, { TEST_PACKAGES: input })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /incompatible_package_profile/)
  }
})

test('RHEL 8/9/10 profile selects the EL layout and the EL major only', async (t) => {
  const root = dependencyFixture(t)
  const body = `id() { printf 0; }; uname() { if [[ \${1-} == -s ]]; then printf Linux; else printf x86_64; fi; }; rpm() { printf x86_64; }
native_dependencies_profile; printf '%s|' "$DEPS_FAMILY" "$DEPS_OS_LABEL" "$DEPS_PG_SUITE" "$DEPS_REDIS_UNIT" "$DEPS_CLAM_SOCKET" "$DEPS_CLAM_GROUP" "\${DEPS_CLAM_UNITS[*]}"`
  for (const [content, expected] of [
    ['ID="rocky"\nVERSION_ID="9.3"\n', 'rhel|rocky=9|rhel-9-x86_64|redis.service|/run/clamd.scan/clamd.sock|virusgroup|clamd@scan.service clamav-freshclam.service|'],
    ['ID="almalinux"\nVERSION_ID="10.2"\n', 'rhel|almalinux=10|rhel-10-x86_64|valkey.service|/run/clamd.scan/clamd.sock|virusgroup|clamd@scan.service clamav-freshclam.service|'],
    ['ID="rhel"\nVERSION_ID="9.8"\n', 'rhel|rhel=9|rhel-9-x86_64|redis.service|/run/clamd.scan/clamd.sock|virusgroup|clamd@scan.service clamav-freshclam.service|'],
    ['ID="rocky"\nVERSION_ID="8.10"\n', 'rhel|rocky=8|rhel-8-x86_64|redis.service|/run/clamd.scan/clamd.sock|virusgroup|clamd@scan.service clamav-freshclam.service|'],
  ]) {
    writeFileSync(join(root, 'os-release'), content)
    const result = await runDependencyFunction(root, body)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, expected)
  }
  for (const content of ['ID="rocky"\nVERSION_ID="7.9"\n', 'ID="centos"\nVERSION_ID="7"\n', 'ID="rocky"\nVERSION_ID="9x"\n', 'ID="rocky"\nID="rocky"\nVERSION_ID="9.3"\n']) {
    writeFileSync(join(root, 'os-release'), content)
    const result = await runDependencyFunction(root, body)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /unsupported_os/)
  }
  writeFileSync(join(root, 'os-release'), 'ID="rocky"\nVERSION_ID="9.3"\n')
  const arm = await runDependencyFunction(root, body.replace('rpm() { printf x86_64; }', 'rpm() { printf aarch64; }'))
  assert.match(arm.stderr, /unsupported_architecture/)
})

test('RHEL package profile accepts only the pinned PostgreSQL 17.11 and ClickHouse rpms', async (t) => {
  const root = dependencyFixture(t)
  const rpms = ['postgresql17-server\t17.11', 'postgresql17\t17.11', 'clickhouse-server\t25.3.6.56', 'clickhouse-client\t25.3.6.56', 'clickhouse-common-static\t25.3.6.56', 'postgresql17-libs\t17.11', 'bash\t5.1.8'].join('\n')
  const body = 'DEPS_FAMILY=rhel DEPS_PG_VERSION=17.11; rpm() { printf "%s\\n" "$TEST_RPMS"; }; native_dependencies_packages'
  for (const [input, expected] of [[rpms, 'installed'], ['bash\t5.1.8', 'fresh']]) {
    const result = await runDependencyFunction(root, body, { TEST_RPMS: input })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), expected)
  }
  for (const input of [rpms.replace('postgresql17-server\t17.11', 'postgresql17-server\t17.10'), rpms.replace('clickhouse-server\t25.3.6.56', 'clickhouse-server\t25.8.1'),
    rpms.split('\n').slice(1).join('\n'), `${rpms}\npostgresql-server\t13.20`, `${rpms}\npostgresql16-server\t16.9`]) {
    const result = await runDependencyFunction(root, body, { TEST_RPMS: input })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /incompatible_package_profile/)
  }
})

test('RHEL clamd@scan configuration keeps vendor comments and sets one socket profile', async (t) => {
  const root = dependencyFixture(t)
  const vendor = '##\n## Example config file for the Clam AV daemon\n#Example\n#LocalSocket /run/clamd.scan/clamd.sock\n#LocalSocketGroup virusgroup\n#LocalSocketMode 660\n#TCPSocket 3310\nUser clamscan\n'
  const config = join(root, 'scan.conf')
  writeFileSync(config, vendor, { mode: 0o644 })
  const body = `DEPS_FAMILY=rhel DEPS_CLAM_CONFIG="$TEST_ROOT/scan.conf" DEPS_CLAM_SOCKET=/run/clamd.scan/clamd.sock DEPS_CLAM_GROUP=virusgroup DEPS_CLAM_USER=clamscan
native_dependencies_rhel_clamav_config; printf '%s' "$DEPS_CLAM_CHANGED"`
  let result = await runDependencyFunction(root, body)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'true')
  const written = readFileSync(config, 'utf8')
  assert.ok(written.startsWith('##\n## Example config file for the Clam AV daemon\n#Example\n#LocalSocket /run/clamd.scan/clamd.sock\n'))
  const active = written.split('\n').filter((line) => line && !line.startsWith('#'))
  assert.deepEqual(active, ['LocalSocket /run/clamd.scan/clamd.sock', 'LocalSocketGroup virusgroup', 'LocalSocketMode 660', 'User clamscan', `DatabaseDirectory ${join(root, 'clamdb')}`])
  result = await runDependencyFunction(root, body)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'false')
  assert.equal(readFileSync(config, 'utf8'), written)
  for (const unexpected of ['TCPSocket 3310\n', 'LocalSocket /tmp/other.sock\n', 'Example\n']) {
    writeFileSync(config, vendor + unexpected, { mode: 0o644 })
    result = await runDependencyFunction(root, body)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /clamav_configuration_mismatch/)
    assert.equal(readFileSync(config, 'utf8'), vendor + unexpected)
  }
})

test('exclusive public configuration creation never overwrites an existing path', async (t) => {
  const root = dependencyFixture(t)
  const target = join(root, 'nested/config')
  let result = await runDependencyFunction(root, 'umask 077; native_dependencies_write_new "$TEST_ROOT/nested/config" 644 "expected"')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(readFileSync(target, 'utf8'), 'expected')
  assert.equal(statSync(target).mode & 0o777, 0o644)
  assert.equal(statSync(join(root, 'nested')).mode & 0o777, 0o755)
  for (const kind of ['regular', 'symlink', 'hardlink']) {
    const destination = join(root, kind)
    if (kind === 'regular') writeFileSync(destination, 'previous')
    else if (kind === 'symlink') symlinkSync(target, destination)
    else linkSync(target, destination)
    result = await runDependencyFunction(root, `native_dependencies_write_new "$TEST_ROOT/${kind}" 644 "replacement"`)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /unsafe_or_existing_path/)
    assert.equal(readFileSync(destination, 'utf8'), kind === 'regular' ? 'previous' : 'expected')
  }
  symlinkSync(join(root, 'nested'), join(root, 'linked-parent'))
  result = await runDependencyFunction(root, 'native_dependencies_write_new "$TEST_ROOT/linked-parent/new" 644 "new"')
  assert.notEqual(result.status, 0)
  assert.equal(existsSync(join(root, 'nested/new')), false)
})

test('repository key verification requires exactly one matching primary fingerprint', async (t) => {
  const root = dependencyFixture(t)
  const fingerprint = 'B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8'
  const body = `gpg() { printf '%s\\n' "$TEST_KEY"; }; native_dependencies_verify_key "$TEST_ROOT/key" '${fingerprint}' "$TEST_ROOT"`
  for (const [key, accepted] of [
    [`pub:::::::::\nfpr:::::::::${fingerprint}:\nsub:::::::::\nfpr:::::::::AAAA:`, true],
    ['pub:::::::::\nfpr:::::::::AAAA:', false],
    [`pub:::::::::\nfpr:::::::::${fingerprint}:\npub:::::::::\nfpr:::::::::BBBB:`, false],
    ['', false],
  ]) {
    const result = await runDependencyFunction(root, body, { TEST_KEY: key })
    assert.equal(result.status === 0, accepted, result.stderr)
    if (!accepted) assert.match(result.stderr, /repository_key_mismatch/)
  }
})

test('loopback configuration must match exact owned bytes and rejects links and unsafe parents', async (t) => {
  const root = dependencyFixture(t)
  const path = join(root, 'clickhouse/config.d/cdnca-loopback.xml')
  const body = 'getent() { if [[ "$1" == passwd ]]; then printf "clickhouse:x:%s:%s::/:/bin/false\\n" "$TEST_UID" "$TEST_GID"; else printf "clickhouse:x:%s:\\n" "$TEST_GID"; fi; }; native_dependencies_loopback check'
  assert.equal((await runDependencyFunction(root, body)).status, 0)
  writeFileSync(path, loopback.replace('127.0.0.1', '0.0.0.0'))
  let result = await runDependencyFunction(root, body.replace('check', 'install'))
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clickhouse_loopback_mismatch/)
  assert.match(readFileSync(path, 'utf8'), /0\.0\.0\.0/)
  writeFileSync(path, loopback)
  chmodSync(path, 0o666)
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
  chmodSync(path, 0o644)
  chmodSync(join(root, 'clickhouse/config.d'), 0o777)
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
})

test('ClickHouse readiness uses only a private client config and rejects non-loopback listeners', async (t) => {
  const root = dependencyFixture(t)
  mkdirSync(join(root, 'analytics'), { mode: 0o700 })
  const admin = join(root, 'analytics/admin.xml')
  writeFileSync(admin, '<config><password>never-print-this</password></config>', { mode: 0o600 })
  const body = `native_dependencies_service() { :; }
systemctl() { printf 123; }
clickhouse-client() { [[ "$*" == *"--config-file $DEPS_ADMIN_CONFIG"* ]] || return 1; printf 25.3.6.56; }
ss() { printf '%s\\n' "$TEST_LISTENERS"; }
native_dependencies_clickhouse`
  const listeners = 'LISTEN 0 4096 127.0.0.1:8123 0.0.0.0:* users:(("clickhouse",pid=123,fd=1))\nLISTEN 0 4096 127.0.0.1:9000 0.0.0.0:* users:(("clickhouse",pid=123,fd=2))'
  let result = await runDependencyFunction(root, body, { TEST_LISTENERS: listeners })
  assert.equal(result.status, 0, result.stderr)
  assert.doesNotMatch(result.stdout + result.stderr, /never-print-this/)
  for (const unsafe of [listeners.replace('127.0.0.1:8123', '0.0.0.0:8123'), `${listeners}\nLISTEN 0 10 [::]:9009 [::]:* users:(("clickhouse",pid=123,fd=3))`, listeners.split('\n')[0]]) {
    result = await runDependencyFunction(root, body, { TEST_LISTENERS: unsafe })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /clickhouse_listener_not_loopback/)
  }
  chmodSync(admin, 0o644)
  result = await runDependencyFunction(root, body, { TEST_LISTENERS: listeners, PYTHONOPTIMIZE: '1' })
  assert.notEqual(result.status, 0)
  assert.doesNotMatch(result.stdout + result.stderr, /never-print-this/)
})

test('service failure is fatal and read-only checks never start services', async (t) => {
  const root = dependencyFixture(t)
  const result = await runDependencyFunction(root, 'systemctl() { printf "%s\\n" "$*" >> "$TEST_ROOT/calls"; return 1; }; native_dependencies_service clickhouse-server.service')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /service_not_ready/)
  assert.doesNotMatch(readFileSync(join(root, 'calls'), 'utf8'), /^(start|enable|restart|stop|disable)\b/m)
})

test('ClamAV config hardening changes only the known vendor socket mode', async (t) => {
  const root = dependencyFixture(t)
  writeFileSync(join(root, 'clamd.conf'), '# vendor example LocalSocketMode 666\nLocalSocket /var/run/clamav/clamd.ctl\nLocalSocketGroup clamav\nLocalSocketMode 666\nUser clamav\nDatabaseDirectory /var/lib/clamav\nKeepThis value\n', { mode: 0o644 })
  let result = await runDependencyFunction(root, 'native_dependencies_clamav_config; printf "%s" "$DEPS_CLAM_CHANGED"')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'true')
  assert.match(readFileSync(join(root, 'clamd.conf'), 'utf8'), /LocalSocketMode 660\n/)
  assert.match(readFileSync(join(root, 'clamd.conf'), 'utf8'), /KeepThis value\n/)
  assert.match(readFileSync(join(root, 'clamd.conf'), 'utf8'), /^# vendor example LocalSocketMode 666\n/)
  result = await runDependencyFunction(root, 'native_dependencies_clamav_config; printf "%s" "$DEPS_CLAM_CHANGED"')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'false')
  writeFileSync(join(root, 'clamd.conf'), 'LocalSocket /private/custom.sock\nLocalSocketMode 666\n', { mode: 0o644 })
  result = await runDependencyFunction(root, 'native_dependencies_clamav_config')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clamav_configuration_mismatch/)
  assert.match(readFileSync(join(root, 'clamd.conf'), 'utf8'), /LocalSocketMode 666/)
})

test('ClickHouse hardening enumerates only approved files and preserves every byte', async (t) => {
  const root = dependencyFixture(t)
  const body = 'getent() { if [[ "$1" == passwd ]]; then printf "clickhouse:x:%s:%s::/:/bin/false\\n" "$TEST_UID" "$TEST_GID"; else printf "clickhouse:x:%s:\\n" "$TEST_GID"; fi; }; native_dependencies_loopback install'
  for (const directory of ['clickhouse', 'clickhouse/config.d', 'clickhouse/users.d']) chmodSync(join(root, directory), 0o700)
  for (const name of ['config.xml', 'users.xml']) chmodSync(join(root, `clickhouse/${name}`), 0o400)
  let result = await runDependencyFunction(root, body)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(statSync(join(root, 'clickhouse')).mode & 0o777, 0o750)
  assert.equal(statSync(join(root, 'clickhouse/config.xml')).mode & 0o777, 0o640)
  assert.equal(readFileSync(join(root, 'clickhouse/config.xml'), 'utf8'), '<clickhouse/>')
  const unknown = join(root, 'clickhouse/config.d/unknown.xml')
  writeFileSync(unknown, '<unknown/>', { mode: 0o600 })
  chmodSync(join(root, 'clickhouse'), 0o700)
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
  assert.equal(statSync(join(root, 'clickhouse')).mode & 0o777, 0o700)
  assert.equal(readFileSync(unknown, 'utf8'), '<unknown/>')
  rmSync(unknown)
  linkSync(join(root, 'clickhouse/users.xml'), join(root, 'linked-users'))
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
  assert.equal(statSync(join(root, 'clickhouse')).mode & 0o777, 0o700)
})

test('unknown ClamAV drop-ins reject before changing the vendor configuration', async (t) => {
  const root = dependencyFixture(t)
  const original = 'LocalSocket /var/run/clamav/clamd.ctl\nLocalSocketGroup clamav\nLocalSocketMode 666\nUser clamav\nDatabaseDirectory /var/lib/clamav\n'
  writeFileSync(join(root, 'clamd.conf'), original, { mode: 0o644 })
  mkdirSync(join(root, 'socket.d'), { mode: 0o755 })
  writeFileSync(join(root, 'socket.d/user.conf'), '[Socket]\nSocketMode=0666\n')
  const result = await runDependencyFunction(root, 'native_dependencies_clamav_config')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clamav_configuration_mismatch/)
  assert.equal(readFileSync(join(root, 'clamd.conf'), 'utf8'), original)
  assert.equal(existsSync(join(root, 'socket.d/cdnca-mode.conf')), false)
})

test('fresh profile refuses prior data and occupied dependency ports without writes', async (t) => {
  const root = dependencyFixture(t)
  const body = `DEPS_PROTECTED_PATHS=("$TEST_ROOT/product-state")
DEPS_PG_KEY="$TEST_ROOT/pg.asc"; DEPS_PG_SOURCE="$TEST_ROOT/pg.sources"; DEPS_CH_KEY="$TEST_ROOT/ch.asc"; DEPS_CH_SOURCE="$TEST_ROOT/ch.sources"
ss() { printf '%s\\n' "$TEST_LISTENERS"; }
native_dependencies_fresh`
  assert.equal((await runDependencyFunction(root, body, { TEST_LISTENERS: '' })).status, 0)
  writeFileSync(join(root, 'product-state'), 'must-not-modify')
  let result = await runDependencyFunction(root, body, { TEST_LISTENERS: '' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /existing_state_requires_review/)
  assert.equal(readFileSync(join(root, 'product-state'), 'utf8'), 'must-not-modify')
  rmSync(join(root, 'product-state'))
  for (const port of [5432, 8123, 9000, 9004, 9005, 9009]) {
    result = await runDependencyFunction(root, body, { TEST_LISTENERS: `LISTEN 0 4096 [::]:${port} [::]:*` })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /dependency_port_in_use/)
  }
  mkdirSync(join(root, 'socket.d'))
  writeFileSync(join(root, 'socket.d/foreign.conf'), 'unknown override')
  result = await runDependencyFunction(root, body, { TEST_LISTENERS: '' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /existing_state_requires_review/)
})

test('fresh installation pins all five packages and writes loopback before package startup', async (t) => {
  const root = dependencyFixture(t)
  const body = `DEPS_NGINX_GUARDS=("$TEST_ROOT/nginx-custom")
native_dependencies_packages() { printf fresh; }
native_dependencies_fresh() { printf 'preflight\\n' >> "$TEST_ROOT/calls"; }
dpkg-query() { if [[ "$TEST_NGINX" == installed ]]; then printf installed; else return 1; fi; }
ss() { printf '%s\\n' "$TEST_LISTENERS"; }
apt-get() { printf 'apt:%s\\n' "$*" >> "$TEST_ROOT/calls"; }
systemctl() { printf 'systemctl:%s\\n' "$*" >> "$TEST_ROOT/calls"; }
native_dependencies_repositories() { printf 'signed-repositories\\n' >> "$TEST_ROOT/calls"; }
native_dependencies_write_new() { printf 'write:%s\\n' "$1" >> "$TEST_ROOT/calls"; }
native_dependencies_loopback() { printf 'loopback-owned\\n' >> "$TEST_ROOT/calls"; }
native_dependencies_clamav_config() { DEPS_CLAM_CHANGED=true; printf 'clamav-config\\n' >> "$TEST_ROOT/calls"; }
timeout() { printf 'freshclam\\n' >> "$TEST_ROOT/calls"; return "$TEST_FRESHCLAM_STATUS"; }
native_dependencies_check() { printf 'checked\\n' >> "$TEST_ROOT/calls"; }
native_dependencies_install`
  let result = await runDependencyFunction(root, body, { TEST_NGINX: 'absent', TEST_LISTENERS: '', TEST_FRESHCLAM_STATUS: '0' })
  assert.equal(result.status, 0, result.stderr)
  let calls = readFileSync(join(root, 'calls'), 'utf8')
  assert.ok(calls.indexOf('preflight') < calls.indexOf('apt:'))
  assert.ok(calls.indexOf('signed-repositories') < calls.indexOf('postgresql-17='))
  assert.ok(calls.indexOf('write:') < calls.indexOf('postgresql-17='))
  assert.match(calls, /postgresql-17=17\.11-1\.pgdg24\.04\+2 postgresql-client-17=17\.11-1\.pgdg24\.04\+2 clickhouse-server=25\.3\.6\.56 clickhouse-client=25\.3\.6\.56 clickhouse-common-static=25\.3\.6\.56/)
  assert.match(calls, /systemctl:disable --now nginx\.service/)
  assert.ok(calls.indexOf('freshclam') < calls.indexOf('checked'))
  writeFileSync(join(root, 'calls'), '')
  result = await runDependencyFunction(root, body, { TEST_NGINX: 'installed', TEST_LISTENERS: '', TEST_FRESHCLAM_STATUS: '0' })
  assert.equal(result.status, 0, result.stderr)
  calls = readFileSync(join(root, 'calls'), 'utf8')
  assert.doesNotMatch(calls, /nginx\.service|\bnginx\b/)
  writeFileSync(join(root, 'calls'), '')
  result = await runDependencyFunction(root, body, { TEST_NGINX: 'absent', TEST_LISTENERS: 'LISTEN 0 10 0.0.0.0:80 0.0.0.0:*', TEST_FRESHCLAM_STATUS: '0' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /nginx_port_in_use/)
  assert.doesNotMatch(readFileSync(join(root, 'calls'), 'utf8'), /apt:|systemctl:/)
  writeFileSync(join(root, 'calls'), '')
  result = await runDependencyFunction(root, body, { TEST_NGINX: 'installed', TEST_LISTENERS: '', TEST_FRESHCLAM_STATUS: '1' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clamav_database_update_failed/)
  assert.doesNotMatch(readFileSync(join(root, 'calls'), 'utf8'), /checked/)
})

test('RHEL fresh install runs freshclam with a world-readable umask (clamd@scan runs as clamscan, files belong to clamupdate)', async (t) => {
  // install-control.sh runs under umask 077: the EL databases became 0600
  // clamupdate and clamd@scan could not load main.cvd (install-smoke S4 rocky9).
  const root = dependencyFixture(t)
  const body = `DEPS_FAMILY=rhel DEPS_EL_MAJOR=9 DEPS_NGINX_GUARDS=()
umask 077
native_dependencies_packages() { printf fresh; }
native_dependencies_fresh() { :; }
rpm() { return 0; }
dnf() { :; }
systemctl() { :; }
native_dependencies_repositories() { :; }
native_dependencies_write_new() { :; }
native_dependencies_loopback() { :; }
native_dependencies_rhel_clamav_config() { :; }
native_dependencies_check() { :; }
pgsetup() { :; }
eval "$(declare -f native_dependencies_rhel_install | sed 's#/usr/pgsql-17/bin/postgresql-17-setup#pgsetup#')"
timeout() { printf 'freshclam umask=%s\\n' "$(umask)" >> "$TEST_ROOT/calls"; }
native_dependencies_install`
  const result = await runDependencyFunction(root, body, {})
  const calls = existsSync(join(root, 'calls')) ? readFileSync(join(root, 'calls'), 'utf8') : ''
  assert.match(calls, /^freshclam umask=0022$/m, result.stderr)
})

test('read-only complete check rejects a running PostgreSQL version mismatch', async (t) => {
  const root = dependencyFixture(t)
  const body = `dpkg-query() { printf '%s\\n' "$TEST_PACKAGES"; }
command() { if [[ "$1" == -v ]]; then return 0; fi; builtin command "$@"; }
nginx() { :; }; native_dependencies_loopback() { :; }
systemctl() { printf '%s\\n' "$*" >> "$TEST_ROOT/calls"; }
pg_lsclusters() { printf '17 main 5432 online postgres fixture fixture\\n'; }
pg_isready() { :; }; runuser() { printf '%s' "$TEST_SERVER_VERSION"; }
redis-cli() { printf PONG; }
native_dependencies_clickhouse() { :; }; native_dependencies_clamav() { :; }
native_dependencies_check`
  let result = await runDependencyFunction(root, body, { TEST_SERVER_VERSION: '170011' })
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /native_dependencies: ready/)
  result = await runDependencyFunction(root, body, { TEST_SERVER_VERSION: '170010' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /postgresql_version_mismatch/)
  assert.doesNotMatch(result.stdout, /ready/)
  assert.doesNotMatch(readFileSync(join(root, 'calls'), 'utf8'), /^(start|enable|restart|stop|disable)\b/m)
})

test('ClamAV checks scans with VERSION disabled, actual database files and a 660 socket', async function verifyClamavColdStart(t) {
  const root = dependencyFixture(t)
  mkdirSync(join(root, 'clamdb'))
  for (const name of ['main.cvd', 'daily.cld']) writeFileSync(join(root, `clamdb/${name}`), 'fixture-db', { mode: 0o644 })
  const config = 'EnableVersionCommand false\nEnableShutdownCommand false\n'
  writeFileSync(join(root, 'clamd.conf'), config, { mode: 0o644 })
  const clean = Buffer.from('cdnca-clamd-readiness-v1\n')
  const eicar = Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
  const requests = []
  let responseMode = 'ready'
  const server = createServer((socket) => {
    let data = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, chunk])
      const commandEnd = data.indexOf(0)
      if (commandEnd < 0) return
      const command = data.subarray(0, commandEnd).toString()
      if (command === 'zINSTREAM') {
        if (data.length < commandEnd + 5) return
        const length = data.readUInt32BE(commandEnd + 1)
        if (data.length < commandEnd + 9 + length) return
        assert.equal(data.length, commandEnd + 9 + length)
        assert.equal(data.readUInt32BE(commandEnd + 5 + length), 0)
        const payload = data.subarray(commandEnd + 5, commandEnd + 5 + length)
        requests.push({ command, payload })
        if (payload.equals(clean)) socket.end(responseMode === 'clean-error' ? 'stream: scan failed ERROR\0' : responseMode === 'clean-found' ? 'stream: Eicar-Signature FOUND\0' : 'stream: OK\0')
        else if (payload.equals(eicar)) socket.end(responseMode === 'eicar-clean' ? 'stream: OK\0' : responseMode === 'eicar-unavailable' ? 'COMMAND UNAVAILABLE\0' : 'stream: Eicar-Signature FOUND\0')
        else socket.end('stream: unexpected probe ERROR\0')
      } else {
        requests.push({ command })
        if (command === 'zPING' && responseMode === 'change-permissions') chmodSync(join(root, 'clamd.ctl'), 0o666)
        if (command === 'zPING' && responseMode === 'ping-timeout') {
          responseMode = 'ready'
          socket.on('end', () => socket.end())
          return
        }
        if (command === 'zPING' && responseMode === 'partial-error') {
          socket.write('WRONG')
          socket.on('end', () => socket.end())
          return
        }
        if (command === 'zPING') socket.end(responseMode === 'ping-error' ? 'ERROR\0' : responseMode === 'bad-frame' ? 'PONG\n' : 'PONG\0')
        else socket.end('COMMAND UNAVAILABLE\0')
      }
    })
  })
  const body = `native_dependencies_service() { :; }
getent() { if [[ "$1" == passwd ]]; then printf "clamav:x:%s:%s::/:/bin/false\\n" "$TEST_UID" "$TEST_GID"; else printf "clamav:x:%s:\\n" "$TEST_GID"; fi; }
timeout() { [[ "$*" == '10 clamd --version' ]] || return 91; printf '%s\\n' "\${TEST_CLAM_VERSION-ClamAV 1.5.4/28000/Thu Oct 8 00:00:00 2026}"; return "\${TEST_CLAM_VERSION_STATUS:-0}"; }
native_dependencies_clamav`
  // Mark an actual missing-socket observation, then start the real Unix server.
  // This test-only wrapper does not alter the production wait deadline.
  const delayedSocket = runDependencyFunction(root, `python3() {
shift 3
command python3 -I -B -c 'import os, sys
original = os.lstat
def observed_lstat(path):
    try: return original(path)
    except FileNotFoundError:
        open(path + ".waiting", "w").close()
        raise
os.lstat = observed_lstat
exec(compile(sys.stdin.read(), "clamav-readiness", "exec"))' "$@"
}
${body}`)
  for (let attempt = 0; attempt < 100 && !existsSync(join(root, 'clamd.ctl.waiting')); attempt++) await new Promise((resolve) => setTimeout(resolve, 50))
  assert.equal(existsSync(join(root, 'clamd.ctl.waiting')), true, 'the readiness check did not observe the delayed socket')
  await new Promise((resolve) => server.listen(join(root, 'clamd.ctl'), resolve))
  t.after(() => new Promise((resolve) => server.close(resolve)))
  chmodSync(join(root, 'clamd.ctl'), 0o660)
  let result = await delayedSocket
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(requests.map(({ command }) => command), ['zPING', 'zINSTREAM', 'zINSTREAM'])
  assert.deepEqual(requests[1].payload, clean)
  assert.deepEqual(requests[2].payload, eicar)
  assert.equal(readFileSync(join(root, 'clamd.conf'), 'utf8'), config)
  assert.doesNotMatch(result.stdout + result.stderr, /ClamAV 1\.5\.4|28000|EICAR-STANDARD/)
  responseMode = 'ping-timeout'
  let count = requests.length
  result = await runDependencyFunction(root, body)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(requests.slice(count).map(({ command }) => command), ['zPING', 'zPING', 'zINSTREAM', 'zINSTREAM'])
  for (responseMode of ['ping-error', 'partial-error', 'bad-frame', 'clean-error', 'clean-found', 'eicar-clean', 'eicar-unavailable', 'change-permissions']) {
    count = requests.length
    result = await runDependencyFunction(root, body)
    assert.notEqual(result.status, 0, responseMode)
    assert.match(result.stderr, /clamav_not_ready/)
    assert.equal(requests.slice(count).filter(({ command }) => command === 'zPING').length, 1, `${responseMode} must not retry`)
    if (responseMode === 'change-permissions') {
      assert.equal(requests.length, count + 1, 'socket safety must be rechecked before the next scan')
      chmodSync(join(root, 'clamd.ctl'), 0o660)
    }
  }
  // Advance only the test clock on retry sleep, not a production timeout knob.
  result = await runDependencyFunction(root, `DEPS_CLAM_SOCKET="$TEST_ROOT/missing.ctl"
python3() {
shift 3
command python3 -I -B -c 'import sys, time
clock = [0]
time.monotonic = lambda: clock[0]
def sleep(seconds): clock[0] += seconds
time.sleep = sleep
try: exec(compile(sys.stdin.read(), "clamav-readiness", "exec"))
finally: print("virtual-wait-seconds=" + str(clock[0]))' "$@"
}
${body}`)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clamav_not_ready/)
  assert.equal(result.stdout.trim(), 'virtual-wait-seconds=120')
  responseMode = 'ready'
  for (const environment of [
    { TEST_CLAM_VERSION: 'ClamAV 1.5.4' },
    { TEST_CLAM_VERSION: 'ClamAV 1.5.4/0/Thu Oct 8 00:00:00 2026' },
    { TEST_CLAM_VERSION: 'ClamAV 1.5.4/28000/date\nextra' },
    { TEST_CLAM_VERSION_STATUS: '1' },
  ]) {
    const count = requests.length
    result = await runDependencyFunction(root, body, environment)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /clamav_not_ready/)
    assert.equal(requests.length, count)
  }
  chmodSync(join(root, 'clamd.ctl'), 0o666)
  count = requests.length
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
  assert.equal(requests.length, count, 'unsafe socket permissions must reject before connecting')
  chmodSync(join(root, 'clamd.ctl'), 0o660)
  rmSync(join(root, 'clamdb/daily.cld'))
  result = await runDependencyFunction(root, body)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /clamav_database_missing/)
})

test('already installed profile never runs apt or changes database state', async (t) => {
  const root = dependencyFixture(t)
  const result = await runDependencyFunction(root, `native_dependencies_packages() { printf installed; }
native_dependencies_loopback() { printf 'loopback:%s\\n' "$1"; }
native_dependencies_clamav_config() { DEPS_CLAM_CHANGED=true; printf clam-config; }
native_dependencies_check() { printf checked; }
apt-get() { printf forbidden >&2; return 99; }
systemctl() { printf '%s\\n' "$*" >> "$TEST_ROOT/calls"; [[ "$*" == 'daemon-reload' || "$*" == 'restart clamav-daemon.socket clamav-daemon.service' || "$*" == 'enable clamav-freshclam.service' || "$*" == 'enable --now postgresql.service postgresql@17-main.service redis-server.service clickhouse-server.service' ]]; }
native_dependencies_install`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'loopback:install\nclam-configchecked')
  assert.doesNotMatch(result.stderr, /forbidden/)
  assert.match(readFileSync(join(root, 'calls'), 'utf8'), /^enable clamav-freshclam\.service$/m)
  assert.doesNotMatch(readFileSync(join(root, 'calls'), 'utf8'), /enable --now clamav-freshclam/)
})

// fix-cleanupreinstall：install-control.sh --cleanup-failed 停止并停用了本次安装启动的 PostgreSQL/Redis/ClickHouse
// （软件包保留）。原命令重装时 helper 走“已装”分支，必须先重新启用并启动这三个服务再做就绪检查，否则 service_not_ready。
test('already installed profile re-enables and starts PostgreSQL, Redis and ClickHouse before the readiness check', async (t) => {
  const root = dependencyFixture(t)
  const stubs = `native_dependencies_packages() { printf installed; }
native_dependencies_loopback() { :; }
native_dependencies_clamav_config() { DEPS_CLAM_CHANGED=false; }
native_dependencies_rhel_clamav_config() { DEPS_CLAM_CHANGED=false; }
native_dependencies_check() { printf 'check\\n' >> "$TEST_ROOT/calls"; }
apt-get() { return 99; }
dnf() { return 99; }
systemctl() { printf '%s\\n' "$*" >> "$TEST_ROOT/calls"; }`
  for (const [profile, expected] of [
    ['', 'enable --now postgresql.service postgresql@17-main.service redis-server.service clickhouse-server.service'],
    ['DEPS_PG_UNITS=(postgresql-17.service)', 'enable --now postgresql-17.service redis-server.service clickhouse-server.service'],
    ['DEPS_FAMILY=rhel DEPS_EL_MAJOR=9 DEPS_REDIS_UNIT=redis.service', 'enable --now postgresql-17.service redis.service clickhouse-server.service'],
    ['DEPS_FAMILY=rhel DEPS_EL_MAJOR=10 DEPS_REDIS_UNIT=valkey.service', 'enable --now postgresql-17.service valkey.service clickhouse-server.service'],
  ]) {
    rmSync(join(root, 'calls'), { force: true })
    const result = await runDependencyFunction(root, `${profile}\n${stubs}\nnative_dependencies_install`)
    assert.equal(result.status, 0, result.stderr)
    const calls = readFileSync(join(root, 'calls'), 'utf8').split('\n')
    const start = calls.indexOf(expected)
    assert.ok(start >= 0, `${profile || 'debian'}: ${calls.join(' | ')}`)
    assert.ok(start < calls.indexOf('check'), 'services start before the readiness check')
  }
})

// fix-btenv：install-control.sh 在宝塔主机上写端口档案，helper 严格解析（不 source）。
const btPorts = 'ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\nPG_PORT=15432\nREDIS_PORT=16379\nCH_HTTP_PORT=18123\nCH_TCP_PORT=19100\nCH_MYSQL_PORT=9004\nCH_POSTGRESQL_PORT=9005\nCH_INTERSERVER_PORT=9009\n'
const portsSetup = 'DEPS_RUNTIME_ENV="$TEST_ROOT/runtime.env"; native_dependencies_ports'

test('端口档案：缺省用默认端口；合法档案生效；非法行、重复键、越界、重复端口与链接一律拒绝', async (t) => {
  const root = dependencyFixture(t)
  const show = `${portsSetup}; printf "%s %s %s %s %s" "$DEPS_ENV" "$DEPS_PG_PORT" "$DEPS_REDIS_PORT" "$DEPS_CH_HTTP_PORT" "$DEPS_CH_TCP_PORT"`
  let result = await runDependencyFunction(root, show)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'plain 5432 6379 8123 9000')
  writeFileSync(join(root, 'runtime.env'), btPorts, { mode: 0o644 })
  result = await runDependencyFunction(root, show)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'bt 15432 16379 18123 19100')
  for (const bad of [btPorts + 'EXTRA=1\n', btPorts + 'PG_PORT=15433\n', 'PG_PORT=80\n', 'PG_PORT=$(id)\n', 'ENV=docker\n', 'PG_PORT=16379\nREDIS_PORT=16379\n']) {
    writeFileSync(join(root, 'runtime.env'), bad, { mode: 0o644 })
    result = await runDependencyFunction(root, show)
    assert.notEqual(result.status, 0, bad)
    assert.match(result.stderr, /invalid_runtime_env/)
  }
  rmSync(join(root, 'runtime.env'))
  writeFileSync(join(root, 'elsewhere.env'), btPorts, { mode: 0o644 })
  symlinkSync(join(root, 'elsewhere.env'), join(root, 'runtime.env'))
  result = await runDependencyFunction(root, show)
  assert.notEqual(result.status, 0)
})

test('ClickHouse 回环配置：默认端口字节不变，替代端口写入同一个文件', async (t) => {
  const root = dependencyFixture(t)
  let result = await runDependencyFunction(root, `${portsSetup}; printf "%s" "$DEPS_LOOPBACK_CONTENT"`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, loopback)
  writeFileSync(join(root, 'runtime.env'), btPorts, { mode: 0o644 })
  result = await runDependencyFunction(root, `${portsSetup}; printf "%s" "$DEPS_LOOPBACK_CONTENT"`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, loopback.replace('</clickhouse>\n', '    <http_port>18123</http_port>\n    <tcp_port>19100</tcp_port>\n</clickhouse>\n'))
})

test('宝塔端口：fresh 只检查实际要用的端口；ClickHouse 就绪检查按替代端口', async (t) => {
  const root = dependencyFixture(t)
  writeFileSync(join(root, 'runtime.env'), btPorts, { mode: 0o644 })
  const fresh = `${portsSetup}; DEPS_PROTECTED_PATHS=("$TEST_ROOT/product-state"); DEPS_PG_KEY="$TEST_ROOT/pg.asc"; DEPS_PG_SOURCE="$TEST_ROOT/pg.sources"; DEPS_CH_KEY="$TEST_ROOT/ch.asc"; DEPS_CH_SOURCE="$TEST_ROOT/ch.sources"
ss() { printf '%s\\n' "$TEST_LISTENERS"; }
native_dependencies_fresh`
  let result = await runDependencyFunction(root, fresh, { TEST_LISTENERS: 'LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:6379 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:8123 0.0.0.0:*' })
  assert.equal(result.status, 0, result.stderr)
  for (const port of [15432, 16379, 18123, 19100]) {
    result = await runDependencyFunction(root, fresh, { TEST_LISTENERS: `LISTEN 0 4096 0.0.0.0:${port} 0.0.0.0:*` })
    assert.notEqual(result.status, 0, String(port))
    assert.match(result.stderr, /dependency_port_in_use/)
  }
  const ready = `${portsSetup}; native_dependencies_service() { :; }
systemctl() { printf 123; }
clickhouse-client() { [[ "$*" == *"--port 19100"* ]] || return 1; printf 25.3.6.56; }
ss() { printf '%s\\n' "$TEST_LISTENERS"; }
native_dependencies_clickhouse`
  result = await runDependencyFunction(root, ready, { TEST_LISTENERS: 'LISTEN 0 4096 127.0.0.1:18123 0.0.0.0:* users:(("clickhouse",pid=123,fd=1))\nLISTEN 0 4096 127.0.0.1:19100 0.0.0.0:* users:(("clickhouse",pid=123,fd=2))' })
  assert.equal(result.status, 0, result.stderr)
})

test('宝塔安装：apt 期间禁止包自启并在启用服务前撤销；有宝塔 nginx 时不装系统 nginx；写入 PostgreSQL 与 Redis 端口', async (t) => {
  const root = dependencyFixture(t)
  writeFileSync(join(root, 'runtime.env'), btPorts, { mode: 0o644 })
  mkdirSync(join(root, 'bt-nginx'))
  writeFileSync(join(root, 'bt-nginx/nginx'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
  writeFileSync(join(root, 'redis.conf'), 'bind 127.0.0.1 -::1\nport 6379\ndaemonize no\n', { mode: 0o640 })
  const body = `${portsSetup}; DEPS_NGINX_GUARDS=("$TEST_ROOT/nginx-custom"); DEPS_BT_NGINX="$TEST_ROOT/bt-nginx/nginx"
DEPS_POLICY_RC="$TEST_ROOT/policy-rc.d"; DEPS_REDIS_CONFIGS=("$TEST_ROOT/redis.conf")
native_dependencies_packages() { printf fresh; }
native_dependencies_fresh() { :; }
dpkg-query() { return 1; }
ss() { printf 'LISTEN 0 10 0.0.0.0:80 0.0.0.0:*\\n'; }
apt-get() { printf 'apt:%s policy=%s\\n' "$*" "$([[ -x $DEPS_POLICY_RC ]] && echo held || echo free)" >> "$TEST_ROOT/calls"; }
systemctl() { printf 'systemctl:%s policy=%s\\n' "$*" "$([[ -e $DEPS_POLICY_RC ]] && echo held || echo free)" >> "$TEST_ROOT/calls"; }
pg_conftool() { printf 'pg_conftool:%s\\n' "$*" >> "$TEST_ROOT/calls"; }
native_dependencies_repositories() { :; }
native_dependencies_write_new() { if [[ $1 == "$DEPS_POLICY_RC" ]]; then printf '%s' "$3" > "$1"; chmod "$2" "$1"; fi; }
native_dependencies_loopback() { :; }
native_dependencies_clamav_config() { DEPS_CLAM_CHANGED=false; }
timeout() { :; }
native_dependencies_check() { printf 'checked\\n' >> "$TEST_ROOT/calls"; }
native_dependencies_install`
  const result = await runDependencyFunction(root, body)
  assert.equal(result.status, 0, result.stderr)
  const calls = readFileSync(join(root, 'calls'), 'utf8')
  for (const line of calls.split('\n').filter((entry) => entry.startsWith('apt:install'))) assert.match(line, /policy=held/, line)
  assert.doesNotMatch(calls, /apt:install[^\n]* nginx /, '宝塔已有 nginx，不装系统 nginx 包')
  assert.match(calls, /pg_conftool:17 main set port 15432/)
  assert.match(calls, /systemctl:enable --now [^\n]*redis-server\.service[^\n]*policy=free/)
  assert.ok(calls.indexOf('pg_conftool:') < calls.indexOf('systemctl:enable --now'))
  assert.equal(existsSync(join(root, 'policy-rc.d')), false)
  assert.match(readFileSync(join(root, 'redis.conf'), 'utf8'), /^port 16379$/m)
})

test('public command accepts no secrets or profile overrides', async (t) => {
  const root = dependencyFixture(t)
  for (const args of ['', 'upgrade', 'install secret', 'check --root /tmp']) {
    const result = await runDependencyFunction(root, `native_dependencies_main ${args}`)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /usage:.*install\|check/)
  }
})

test('hosts without a PGDG 17.11 package select the pinned portable PostgreSQL build', async (t) => {
  const root = dependencyFixture(t)
  const body = 'id() { printf 0; }; uname() { if [[ ${1-} == -s ]]; then printf Linux; else printf x86_64; fi; }; dpkg() { printf amd64; }; native_dependencies_profile; printf "%s|%s|%s|%s|%s" "$DEPS_PG_MODE" "$DEPS_OS_LABEL" "${DEPS_PG_UNITS[*]}" "$DEPS_PG_DATA" "$DEPS_PG_PSQL"; native_dependencies_requirements'
  for (const [content, label] of [
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'ubuntu=20.04'],
    ['ID=debian\nVERSION_ID="11"\nVERSION_CODENAME=bullseye\n', 'debian=11'],
    ['ID=debian\nVERSION_ID="10"\nVERSION_CODENAME=buster\n', 'debian=10'],
  ]) {
    writeFileSync(join(root, 'os-release'), content)
    const result = await runDependencyFunction(root, body)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, new RegExp(`^portable\\|${label}\\|postgresql-17\\.service\\|/var/lib/pgsql/17/data\\|/usr/bin/psql` +
      'postgresql postgresql-17\\.11-portable-linux-amd64\\.tar\\.gz e58f34528c56ff3557ecaa6164ab45ebc7dcce26f23cf92d596183cd8b816cb0\n' +
      'clamav clamav-1\\.4\\.6-portable-linux-amd64\\.tar\\.gz [0-9a-f]{64}\n$'))
  }
  writeFileSync(join(root, 'os-release'), 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
  const packaged = await runDependencyFunction(root, body)
  assert.equal(packaged.status, 0, packaged.stderr)
  assert.match(packaged.stdout, /^package\|ubuntu=24\.04\|postgresql\.service postgresql@17-main\.service\|/)
  assert.doesNotMatch(packaged.stdout, /portable-linux-amd64/)
})

test('portable package profile: no PostgreSQL package at all, receipt decides installed', async (t) => {
  const root = dependencyFixture(t)
  const clickhouse = ['clickhouse-server', 'clickhouse-client', 'clickhouse-common-static'].map((name) => `${name}\tinstalled\t25.3.6.56`).join('\n')
  const body = `native_dependencies_portable_pg_profile; DEPS_PG_PORTABLE_RECEIPT="$TEST_ROOT/receipt"
dpkg-query() { printf "%s\\n" "$TEST_PACKAGES"; }; native_dependencies_packages`
  let result = await runDependencyFunction(root, body, { TEST_PACKAGES: '' })
  assert.equal(result.stdout.trim(), 'fresh', result.stderr)
  result = await runDependencyFunction(root, body, { TEST_PACKAGES: clickhouse })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /incompatible_package_profile/)
  writeFileSync(join(root, 'receipt'), 'x')
  result = await runDependencyFunction(root, body, { TEST_PACKAGES: clickhouse })
  assert.equal(result.stdout.trim(), 'installed', result.stderr)
  for (const extra of ['postgresql-12\tinstalled\t12.22', 'postgresql-client-10\tinstalled\t10.23']) {
    result = await runDependencyFunction(root, body, { TEST_PACKAGES: `${clickhouse}\n${extra}` })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /incompatible_package_profile/)
  }
  result = await runDependencyFunction(root, body, { TEST_PACKAGES: '' })
  assert.notEqual(result.status, 0, 'a receipt without the packages is not fresh')
})

test('portable archive is refused unless it matches the pin, before anything is unpacked', async (t) => {
  const root = dependencyFixture(t)
  writeFileSync(join(root, 'archive.tar.gz'), 'not the pinned archive')
  const body = `native_dependencies_portable_pg_profile; DEPS_PG_PORTABLE_PREFIX="$TEST_ROOT/opt/pg"
tar() { printf unpacked >> "$TEST_ROOT/calls"; }
native_dependencies_portable_pg_install "$TEST_ROOT/$TEST_ARCHIVE"`
  for (const [archive, code] of [['archive.tar.gz', 'portable_postgresql_archive_mismatch'], ['missing.tar.gz', 'portable_postgresql_archive_missing']]) {
    const result = await runDependencyFunction(root, body, { TEST_ARCHIVE: archive })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, new RegExp(code))
  }
  symlinkSync(join(root, 'archive.tar.gz'), join(root, 'link.tar.gz'))
  const linked = await runDependencyFunction(root, body, { TEST_ARCHIVE: 'link.tar.gz' })
  assert.match(linked.stderr, /portable_postgresql_archive_missing/)
  assert.equal(existsSync(join(root, 'calls')), false)
})

test('install takes the portable archive exactly when the host needs it', async (t) => {
  const root = dependencyFixture(t)
  const prefix = 'id() { printf 0; }; uname() { if [[ ${1-} == -s ]]; then printf Linux; else printf x86_64; fi; }; dpkg() { printf amd64; }; native_dependencies_install() { printf "install:%s" "$DEPS_PG_PORTABLE_INPUT"; }; native_dependencies_write_new() { :; }; native_dependencies_path() { :; }; flock() { :; }; command() { [[ "$1" == -v ]] || builtin command "$@"; }; DEPS_LOCK="$TEST_ROOT/lock"; '
  for (const [release, args, ok] of [
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install --postgresql-archive /tmp/a.tar.gz --clamav-archive /tmp/c.tar.gz', true],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install --clamav-archive /tmp/c.tar.gz --postgresql-archive /tmp/a.tar.gz', true],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install --postgresql-archive /tmp/a.tar.gz', false],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install --postgresql-archive /tmp/a.tar.gz --postgresql-archive /tmp/b.tar.gz', false],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install --postgresql-archive', false],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'install', false],
    ['ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal\n', 'check --postgresql-archive /tmp/a.tar.gz', false],
    ['ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', 'install --postgresql-archive /tmp/a.tar.gz', false],
    ['ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n', 'install', true],
  ]) {
    writeFileSync(join(root, 'os-release'), release)
    const result = await runDependencyFunction(root, `${prefix} native_dependencies_main ${args}`)
    assert.equal(result.status === 0, ok, `${args}: ${result.stderr}`)
    if (!ok) assert.match(result.stderr, /usage:/)
  }
})
