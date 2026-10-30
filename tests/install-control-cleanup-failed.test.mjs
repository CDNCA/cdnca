// AUDIT-1029 ①-12：主控全新安装半途失败后，原命令重跑被空机门禁拒绝且无出路。
// 主控不支持续装（签名辅助脚本只做全新安装、密钥/口令每次重新生成），
// 改为 --cleanup-failed：只删安装记录之后由本安装器创建的东西，需确认；安装前已有的路径不动。
// 真实脚本中的所有绝对路径改写到临时根目录下运行，systemctl/psql 等打桩；不碰宿主。
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const script = source.replace(/^main "\$@"\s*$/m, '')

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-control-cleanup-'))
  let isolated = script
  for (const prefix of ['/usr/local', '/usr/share', '/etc', '/var/lib', '/var/log', '/run', '/data', '/opt']) {
    isolated = isolated.replace(new RegExp(`(?<=["'=\\s(])${prefix}(?=/|["'\\s;)]|$)`, 'g'), join(root, prefix.slice(1)))
  }
  const bin = join(root, 'bin')
  mkdirSync(bin)
  const stub = (name, body) => { writeFileSync(join(bin, name), `#!/bin/bash\n${body}\n`); chmodSync(join(bin, name), 0o755) }
  for (const name of ['nft', 'userdel', 'groupdel', 'update-ca-certificates', 'clickhouse-client', 'runuser', 'psql']) {
    stub(name, `echo "${name} $*" >> "${root}/calls.log"; [ "${name}" != clickhouse-client ] && [ "${name}" != runuser ] || cat >> "${root}/sql.log"; exit 0`)
  }
  // systemctl show：FIXTURE_UNITS 里的单元已加载（redis.service 是 redis-server.service 的别名），其余 not-found；
  // FIXTURE_SYSTEMCTL_BROKEN 时 show 失败（无法判定）。其余子命令只记录。
  stub('systemctl', `echo "systemctl $*" >> "${root}/calls.log"
if [ "$1" = show ]; then
  [ -z "\${FIXTURE_SYSTEMCTL_BROKEN:-}" ] || exit 1
  unit=\${@: -1}; id=$unit; [ "$unit" != redis.service ] || id=redis-server.service
  case " \${FIXTURE_UNITS:-} " in *" $id "*) [ "$3" = Id ] && echo "$id" || echo loaded ;; *) [ "$3" = Id ] && echo "$unit" || echo not-found ;; esac
fi
# FIXTURE_INACTIVE 里的单元未运行且未启用（别名不在列表里，systemd 对别名 is-enabled 报 alias 并返回 0）。
if [ "$1" = is-active ] || [ "$1" = is-enabled ]; then case " \${FIXTURE_INACTIVE:-} " in *" \${@: -1} "*) exit 1 ;; esac; fi
exit 0`)
  // getent：账户是否存在由 FIXTURE_ACCOUNT 决定。
  stub('getent', '[ -n "${FIXTURE_ACCOUNT:-}" ] && [ "$2" = cdnca-objectstore ] && echo "cdnca-objectstore:x:999:999::/x:/bin/false" && exit 0; exit 2')
  // stat -c '%u:%h:%a'：macOS 的 stat 不支持 -c，按真实文件位数回答。
  stub('stat', 'f=${@: -1}; m=$(perl -e "printf q(%o), (stat(\\$ARGV[0]))[2] & 07777" "$f"); echo "0:1:$m"')
  const file = (path, contents = '', mode = 0o600) => {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, contents, { mode })
    return target
  }
  const run = (body, { env = {}, input } = {}) => spawnSync('bash', ['-c', `${isolated}\n${body}`, 'fixture'], {
    encoding: 'utf8', input, timeout: 20000,
    env: { PATH: `${bin}:/usr/bin:/bin`, PROGRESS_LOG_DIR: join(root, 'var/log'), ...env },
  })
  const calls = () => (existsSync(join(root, 'calls.log')) ? readFileSync(join(root, 'calls.log'), 'utf8') : '')
  const sql = () => (existsSync(join(root, 'sql.log')) ? readFileSync(join(root, 'sql.log'), 'utf8') : '')
  return { root, file, run, calls, sql, exists: (path) => existsSync(join(root, path)) }
}

test('a fresh install records preexisting candidate paths before creating anything', () => {
  const value = fixture()
  try {
    value.file('usr/local/libexec/cdnca/cdnca-ed25519', 'tool', 0o555)
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    const result = value.run('control_install_state_begin; cat "$CONTROL_INSTALL_STATE_FILE"')
    assert.equal(result.status, 0, result.stderr)
    const lines = result.stdout.trim().split('\n')
    assert.equal(lines[0], 'schema=cdnca.control-install-state/v1')
    assert.ok(lines.includes(`preexisting=${join(value.root, 'usr/local/libexec/cdnca')}`), result.stdout)
    assert.ok(!lines.some((line) => line.includes('/etc/cdnca-control')), 'nothing else existed')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('the record notes which dependency services existed before the install', () => {
  const value = fixture()
  try {
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    const result = value.run('control_install_state_begin; cat "$CONTROL_INSTALL_STATE_FILE"',
      { env: { FIXTURE_UNITS: 'redis-server.service' } })
    assert.equal(result.status, 0, result.stderr)
    const lines = result.stdout.trim().split('\n')
    for (const unit of ['postgresql.service', 'postgresql@17-main.service', 'postgresql-17.service', 'valkey.service', 'clickhouse-server.service']) {
      assert.ok(lines.includes(`service-absent=${unit}`), `${unit}: ${result.stdout}`)
    }
    assert.ok(lines.includes('preexisting=service:redis-server.service'), result.stdout)
    assert.ok(lines.includes('preexisting=service:redis.service'), 'an alias of a preexisting unit is preexisting too')
    const broken = fixture()
    try {
      mkdirSync(join(broken.root, 'var/lib'), { recursive: true })
      const unknown = broken.run('control_install_state_begin; cat "$CONTROL_INSTALL_STATE_FILE"', { env: { FIXTURE_SYSTEMCTL_BROKEN: '1' } })
      assert.equal(unknown.status, 0, unknown.stderr)
      assert.doesNotMatch(unknown.stdout, /service-absent=|preexisting=service:/, 'undeterminable services are not recorded')
    } finally { rmSync(broken.root, { recursive: true, force: true }) }
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

// fix-cleanupreinstall：清理后原命令重装，第二轮记录里这些服务已装但已停止停用。它们若记成 preexisting，
// 第二轮再失败时清理不会停它们，第三次重装又卡在端口预检。已加载但未运行且未启用的记 service-inactive=，
// 清理时与 service-absent= 同样停止并停用（恰好恢复记录时的状态）。
test('a loaded but stopped and disabled dependency is recorded as inactive and stopped again by the cleanup', () => {
  const value = fixture()
  try {
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    const units = 'postgresql.service postgresql@17-main.service redis-server.service clickhouse-server.service'
    const begin = value.run('control_install_state_begin; cat "$CONTROL_INSTALL_STATE_FILE"',
      { env: { FIXTURE_UNITS: units, FIXTURE_INACTIVE: 'postgresql.service postgresql@17-main.service redis-server.service' } })
    assert.equal(begin.status, 0, begin.stderr)
    const lines = begin.stdout.trim().split('\n')
    for (const unit of ['postgresql.service', 'postgresql@17-main.service', 'redis-server.service']) {
      assert.ok(lines.includes(`service-inactive=${unit}`), `${unit}: ${begin.stdout}`)
      assert.ok(!lines.includes(`preexisting=service:${unit}`), unit)
    }
    assert.ok(lines.includes('preexisting=service:clickhouse-server.service'), 'running or enabled stays preexisting')
    assert.ok(lines.includes('preexisting=service:redis.service'), 'alias of an inactive unit is never acted upon')
    rmSync(join(value.root, 'var/lib/cdnca-control-install'), { recursive: true, force: true })
    rmSync(join(value.root, 'calls.log'), { force: true })
    halfInstalled(value, lines.filter((line) => /^(service-|preexisting=service:)/.test(line)))
    const result = value.run('ASSUME_YES=true; cleanup_failed_run', { env: { FIXTURE_UNITS: units } })
    assert.equal(result.status, 0, result.stderr)
    const calls = value.calls()
    for (const unit of ['postgresql.service', 'postgresql@17-main.service', 'redis-server.service']) {
      assert.match(calls, new RegExp(`^systemctl stop ${unit.replace(/[.@]/g, '\\$&')}$`, 'm'))
      assert.match(calls, new RegExp(`^systemctl disable ${unit.replace(/[.@]/g, '\\$&')}$`, 'm'))
    }
    assert.doesNotMatch(calls, /^systemctl (stop|disable) (clickhouse-server|redis)\.service$/m)
    assert.doesNotMatch(result.stderr, /人工处理/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

function halfInstalled(value, extra = []) {
  mkdirSync(join(value.root, 'var/lib/cdnca-control-install'), { recursive: true, mode: 0o700 })
  value.file('var/lib/cdnca-control-install/state', ['schema=cdnca.control-install-state/v1',
    `preexisting=${join(value.root, 'usr/local/libexec/cdnca')}`, 'step=dependencies_ready', 'created=postgresql:5432',
    'created=clickhouse:9000', ...extra, ''].join('\n'))
  // 依赖服务：PostgreSQL/Redis 由本次安装装上并启动；ClickHouse 安装前已存在。
  value.file('etc/cdnca-control/control.env', 'DATABASE_URL=redacted\n')
  value.file('etc/cdnca-analytics/admin.xml', '<config/>')
  value.file('data/cdnca-native-root/cdnca/current/bin/control-api', 'bin', 0o755)
  value.file('usr/local/libexec/cdnca/cdnca-ed25519', 'tool', 0o555)
  value.file('etc/systemd/system/cdnca-control-api.service', '[Unit]\n')
  value.file('etc/systemd/system/cdnca-objectstore.service', '[Unit]\n')
  value.file('etc/redis/redis.conf', `port 6379\n\ninclude ${join(value.root, 'etc/redis/cdnca-gateway/redis-gateway.conf')}\n`)
  value.file('etc/redis/cdnca-gateway/redis-gateway.conf', 'requirepass x\n')
  value.file('etc/letsencrypt/live/console.cdnca.com/fullchain.pem', 'cert')
  value.file('var/lib/postgresql/17/main/PG_VERSION', '17')
}

test('rerunning the fresh installer after a failure points at --cleanup-failed', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    const result = value.run('assert_fresh_installation')
    assert.equal(result.status, 1)
    assert.match(result.stderr, /主控安装不支持续装.*--cleanup-failed/)
    assert.match(result.stderr, /run install-control.sh --cleanup-failed first/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('--cleanup-failed lists exactly what the install created and needs confirmation', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    const result = value.run('cleanup_failed_run', { input: '' })
    assert.equal(result.status, 1, 'no terminal and no --yes must refuse')
    assert.match(result.stderr, /cleanup needs confirmation/)
    assert.match(result.stderr, /etc\/cdnca-control\n/)
    assert.match(result.stderr, /systemd 单元（停止、停用、删除）：cdnca-control-api\.service/)
    assert.match(result.stderr, /PostgreSQL（端口 5432）：数据库 cdnca/)
    assert.match(result.stderr, /ClickHouse（端口 9000）：数据库 cdnca_analytics/)
    assert.match(result.stderr, /Redis 配置中本安装追加的 include 行/)
    assert.doesNotMatch(result.stderr, /libexec\/cdnca\n/, 'preexisting path is not listed')
    assert.doesNotMatch(result.stderr, /letsencrypt\/live|postgresql\/17/)
    // 确认前只允许只读查询（nft list）。
    assert.equal(value.calls().split('\n').filter((line) => line && !line.startsWith('nft list ') && !line.startsWith('systemctl show ')).join('\n'), '',
      'nothing changed before confirmation')
    assert.ok(value.exists('etc/cdnca-control/control.env'))
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('--cleanup-failed --yes removes only what the install created', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    // cleanup_failed_main 先做 root 与记录检查（测试不以 root 运行），再调用 cleanup_failed_run。
    const result = value.run('ASSUME_YES=true; cleanup_failed_run', { env: { FIXTURE_ACCOUNT: '1' } })
    assert.equal(result.status, 0, result.stderr)
    for (const gone of ['etc/cdnca-control', 'etc/cdnca-analytics', 'data/cdnca-native-root/cdnca', 'etc/redis/cdnca-gateway',
      'etc/systemd/system/cdnca-control-api.service', 'var/lib/cdnca-control-install']) {
      assert.ok(!value.exists(gone), `${gone} must be removed`)
    }
    for (const kept of ['usr/local/libexec/cdnca/cdnca-ed25519', 'etc/letsencrypt/live/console.cdnca.com/fullchain.pem',
      'var/lib/postgresql/17/main/PG_VERSION', 'etc/redis/redis.conf']) {
      assert.ok(value.exists(kept), `${kept} must be kept`)
    }
    assert.equal(readFileSync(join(value.root, 'etc/redis/redis.conf'), 'utf8').includes('include'), false)
    assert.match(readFileSync(join(value.root, 'etc/redis/redis.conf'), 'utf8'), /port 6379/)
    const calls = value.calls()
    assert.match(calls, /systemctl disable --now .*cdnca-control-api\.service/)
    assert.match(calls, /userdel cdnca-objectstore/)
    assert.match(value.sql(), /DROP DATABASE IF EXISTS cdnca WITH \(FORCE\);[\s\S]*DROP ROLE IF EXISTS cdnca;/)
    assert.match(value.sql(), /DROP DATABASE IF EXISTS cdnca_analytics SYNC/)
    assert.match(calls, /clickhouse-client .*--config-file .*cdnca-analytics\/admin\.xml/)
    // 删库发生在删 /etc/cdnca-analytics（ClickHouse 管理口令）之前。
    assert.match(result.stdout, /dropped the cdnca PostgreSQL database and roles\n.*dropped the cdnca_analytics ClickHouse database/s)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

// 依赖服务：PostgreSQL、Redis（含别名 redis.service）安装前不存在、现在已加载 → 停止并停用；
// ClickHouse 安装前已存在 → 不动；valkey 记录里没有结论 → 列入人工处理、不动。
const dependencyRecord = ['service-absent=postgresql.service', 'service-absent=postgresql@17-main.service',
  'service-absent=postgresql-17.service', 'service-absent=redis-server.service', 'service-absent=redis.service',
  'preexisting=service:clickhouse-server.service']
const dependencyUnits = 'postgresql.service postgresql@17-main.service redis-server.service clickhouse-server.service valkey.service'

test('--cleanup-failed lists the dependency services this install started and the ones it cannot judge', () => {
  const value = fixture()
  try {
    halfInstalled(value, dependencyRecord)
    const result = value.run('cleanup_failed_run', { input: '', env: { FIXTURE_UNITS: dependencyUnits } })
    assert.equal(result.status, 1)
    for (const unit of ['postgresql.service', 'postgresql@17-main.service', 'redis-server.service']) {
      assert.match(result.stderr, new RegExp(`依赖服务（本次安装装上并启动；停止并停用以释放端口，软件包与数据目录保留）：${unit.replace(/[.@]/g, '\\$&')}\n`))
    }
    assert.doesNotMatch(result.stderr, /依赖服务（[^\n]*(clickhouse-server|redis\.service|valkey)/, 'preexisting, alias and unknown are not stopped')
    assert.match(result.stderr, /无法判定是否由本次安装启动，不动，请人工处理[^\n]*：valkey\.service/)
    assert.doesNotMatch(result.stderr, /人工处理[^\n]*(clickhouse|postgresql-17)/, 'not loaded or preexisting needs no hand work')
    assert.match(result.stderr, /保留：安装前已存在的软件包、服务与路径/)
    assert.doesNotMatch(value.calls(), /systemctl (stop|disable)/, 'nothing stopped before confirmation')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('--cleanup-failed --yes stops and disables only the dependency services this install started, after dropping the databases', () => {
  const value = fixture()
  try {
    halfInstalled(value, dependencyRecord)
    const result = value.run('ASSUME_YES=true; cleanup_failed_run', { env: { FIXTURE_UNITS: dependencyUnits } })
    assert.equal(result.status, 0, result.stderr)
    const calls = value.calls()
    for (const unit of ['postgresql.service', 'postgresql@17-main.service', 'redis-server.service']) {
      assert.match(calls, new RegExp(`^systemctl stop ${unit.replace(/[.@]/g, '\\$&')}$`, 'm'))
      assert.match(calls, new RegExp(`^systemctl disable ${unit.replace(/[.@]/g, '\\$&')}$`, 'm'))
    }
    assert.doesNotMatch(calls, /^systemctl (stop|disable) .*(clickhouse-server|valkey|redis\.service|postgresql-17)/m)
    assert.ok(calls.indexOf('clickhouse-client') < calls.indexOf('systemctl stop postgresql.service'), 'databases dropped first')
    assert.ok(value.exists('var/lib/postgresql/17/main/PG_VERSION'), 'data directory kept')
    assert.doesNotMatch(calls, /apt-get|dnf|userdel postgres/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('--cleanup-failed refuses a completed installation and a missing record', () => {
  const value = fixture()
  try {
    // 记录检查在 root 检查之后：把 EUID 判断换成恒真再跑真实的 cleanup_failed_main。
    const main = (extra = '') => value.run(`eval "$(declare -f cleanup_failed_main | sed 's/\\[ "\\$EUID" -eq 0 \\]/true/')"; ${extra} cleanup_failed_main --yes`)
    const missing = main()
    assert.equal(missing.status, 1)
    assert.match(missing.stderr, /no install record/)
    halfInstalled(value, ['step=done'])
    const done = main()
    assert.equal(done.status, 1)
    assert.match(done.stderr, /never removes a working control plane/)
    assert.ok(value.exists('etc/cdnca-control/control.env'), 'a completed install is untouched')
    assert.equal(value.calls(), '')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('main wires the record, the cleanup entry point and the database markers', () => {
  const main = source.match(/^main\(\) \{[\s\S]*?^\}\n/m)?.[0] ?? ''
  assert.match(main, /--cleanup-failed \] \|\| \{ shift; cleanup_failed_main "\$@"; return; \}/)
  const lock = main.indexOf('acquire_control_install_lock'), begin = main.indexOf('control_install_state_begin')
  assert.ok(lock > -1 && begin > main.indexOf('assert_fresh_installation', lock), 'record after the locked blank-host gate')
  assert.ok(begin < main.indexOf('download_native_support'), 'record before the first host write')
  assert.ok(main.indexOf('control_install_state_done') > main.indexOf('setup_community_identity_refresh'))
  // fail2ban（ssh_guard_setup）装在记录建立之前：未安装的依赖包要先取下来。
  assert.ok(main.indexOf('control_install_state_prepare') > -1 && main.indexOf('control_install_state_prepare') < main.indexOf('ssh_guard_setup'))
  assert.match(source, /install-ubuntu-dependencies\.sh" "\$action" \$\{inputs\[@\]\+"\$\{inputs\[@\]\}"\}\n\s+# [^\n]*\n\s+control_install_state_add step=dependencies_ready/)
  assert.match(source, /control_install_state_add "created=postgresql:\$\{PG_PORT\}"\n\s+"\$\{psql_runner\[@\]\}" -X -v ON_ERROR_STOP=1 --dbname postgres <"\$sql_file"/)
  assert.match(source, /control_install_state_add "created=clickhouse:\$\{CH_TCP_PORT\}"\n\s+progress_run '初始化 ClickHouse'/)
  assert.match(source.match(/^cleanup\(\) \{[\s\S]*?^\}\n/m)[0], /\[ "\$status" -eq 0 \] \|\| control_install_failed_hint/)
})

// fix-cleanupresidue：社区冒烟报"依赖装完、RustFS 与 ClamAV 配置写完后失败"重跑被残留拦。RustFS 助手的全新安装
// 门禁（install-rustfs.py FRESH_PATHS + 账户）与空机门禁的每个路径都必须在清理清单里；/usr/lib、/run 下的单元
// 不是本安装器写的，不在此列。
test('every path the RustFS fresh-install gate refuses is removed by --cleanup-failed', () => {
  const rustfs = readFileSync(new URL('../scripts/native-runtime/install-rustfs.py', import.meta.url), 'utf8')
  const constants = Object.fromEntries([...rustfs.matchAll(/^([A-Z_]+) = Path\("([^"]+)"\)$/gm)].map((m) => [m[1], m[2]]))
  const block = rustfs.match(/^FRESH_PATHS = \(([\s\S]*?)\)\n/m)[1]
  const fresh = [...block.matchAll(/Path\(str\(UNIT\) \+ "\.d"\)|Path\("([^"]+)"\)|\b([A-Z_]+)\b/g)]
    .map((m) => (m[0].startsWith('Path(str(UNIT)') ? `${constants.UNIT}.d` : m[1] ?? constants[m[2]]))
    .filter((path) => path && !path.startsWith('/usr/lib/systemd/') && !path.startsWith('/run/'))
  assert.ok(fresh.length >= 9, fresh.join(' '))
  // 用未改写路径的真实脚本列清单（夹具的路径改写不覆盖 printf 格式串里 \n 之后的路径）。
  const owned = spawnSync('bash', ['-c', `${script}\ncontrol_install_owned_paths`], { encoding: 'utf8' }).stdout.split('\n')
  for (const path of fresh) {
    assert.ok(owned.some((item) => item && (path === item || path.startsWith(`${item}/`))), `${path} not cleaned`)
  }
})

test('cleanup after RustFS and ClamAV were configured removes RustFS and the install root, keeps the ClamAV drop-in', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    for (const path of ['etc/cdnca-objectstore/root-secret-key', 'etc/cdnca-objectstore/ca.crt', 'var/lib/cdnca-objectstore/.keep',
      'var/lib/cdnca-objectstore-logs/.keep', 'usr/local/share/ca-certificates/cdnca-objectstore.crt', 'etc/ssl/certs/cdnca-objectstore.pem',
      'usr/local/cdnca-control/support/install-ubuntu-dependencies.sh']) value.file(path, 'x')
    value.file('usr/local/lib/cdnca-runtime/rustfs', 'bin', 0o755)
    // 依赖 helper 写的配置：包已装时 helper 的已装分支要求它们原样存在，清理不能删。
    const dropin = value.file('etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf', '[Socket]\nSocketMode=0660\n', 0o644)
    const loopback = value.file('etc/clickhouse-server/config.d/cdnca-loopback.xml', '<clickhouse/>', 0o644)
    depFixture(value, true)
    const result = value.run('ASSUME_YES=true; cleanup_failed_run; assert_fresh_installation', { env: { FIXTURE_ACCOUNT: '1' } })
    assert.equal(result.status, 0, result.stderr)
    for (const path of ['etc/cdnca-objectstore', 'var/lib/cdnca-objectstore', 'var/lib/cdnca-objectstore-logs', 'usr/local/lib/cdnca-runtime',
      'usr/local/share/ca-certificates/cdnca-objectstore.crt', 'etc/ssl/certs/cdnca-objectstore.pem', 'usr/local/cdnca-control',
      'etc/systemd/system/cdnca-objectstore.service']) assert.ok(!value.exists(path), `${path} kept`)
    assert.match(value.calls(), /^userdel cdnca-objectstore$/m)
    assert.ok(existsSync(dropin) && existsSync(loopback), 'dependency helper configuration kept')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

// 依赖 helper 在“写完 ClamAV drop-in、软件源、ClickHouse 回环配置，装包之前/之中”失败：包未装上，重跑走 helper 的
// 全新分支（native_dependencies_fresh），这些文件全部被拒（existing_state_requires_review）。包未装上时清理删掉本次写的；
// 包已装上时 helper 走已装分支并要求它们原样存在，保留。安装前已有的不动。
const depLeftovers = ['etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf', 'usr/share/keyrings/cdnca-pgdg.asc',
  'usr/share/keyrings/cdnca-clickhouse.asc', 'etc/apt/sources.list.d/cdnca-pgdg.sources', 'etc/apt/sources.list.d/cdnca-clickhouse.list',
  'etc/clickhouse-server/config.d/cdnca-loopback.xml']
// 社区版以安装记录 step=dependencies_ready（依赖 helper 跑完并就绪）判定依赖已装完。
function depFixture(value, installed) {
  writeFileSync(join(value.root, 'bin', 'rpm'), '#!/bin/bash\nexit 1\n', { mode: 0o755 })
  if (installed) writeFileSync(join(value.root, 'var/lib/cdnca-control-install/state'), 'step=dependencies_ready\n', { flag: 'a' })
}

test('cleanup removes the dependency helper files when the packages never got installed', () => {
  const value = fixture()
  try {
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    value.file('usr/share/keyrings/operator.asc', 'keep', 0o644)
    assert.equal(value.run('control_install_state_begin').status, 0)
    for (const path of depLeftovers) value.file(path, 'x', 0o644)
    depFixture(value, false)
    // 宿主 bash 3.2 空数组在 set -u 下报 unbound（生产 bash ≥ 4.4 无此问题）：放本次安装的单元与 Redis include。
    value.file('etc/systemd/system/cdnca-control-api.service', '[Unit]\n')
    value.file('etc/redis/redis.conf', `include ${join(value.root, 'etc/redis/cdnca-gateway/redis-gateway.conf')}\n`)
    const result = value.run('ASSUME_YES=true; cleanup_failed_run')
    assert.equal(result.status, 0, result.stderr)
    for (const path of depLeftovers) assert.ok(!value.exists(path), `${path} kept`)
    for (const path of ['etc/systemd/system/clamav-daemon.socket.d', 'etc/clickhouse-server']) assert.ok(!value.exists(path), `${path} kept`)
    assert.ok(value.exists('usr/share/keyrings/operator.asc'), 'unrelated file removed')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('cleanup keeps the dependency helper files when the packages are installed or they predate the install', () => {
  for (const mode of ['installed', 'preexisting']) {
    const value = fixture()
    try {
      mkdirSync(join(value.root, 'var/lib'), { recursive: true })
      if (mode === 'preexisting') for (const path of depLeftovers) value.file(path, 'x', 0o644)
      assert.equal(value.run('control_install_state_begin').status, 0)
      if (mode === 'installed') for (const path of depLeftovers) value.file(path, 'x', 0o644)
      depFixture(value, mode === 'installed')
      value.file('etc/systemd/system/cdnca-control-api.service', '[Unit]\n')
      const result = value.run('ASSUME_YES=true; cleanup_failed_run')
      assert.equal(result.status, 0, result.stderr)
      for (const path of depLeftovers) assert.ok(value.exists(path), `${mode}: ${path} removed`)
    } finally { rmSync(value.root, { recursive: true, force: true }) }
  }
})

// 社区版（98 冒烟）：依赖装到一半失败，重装被 PG/Redis/ClickHouse/ClamAV/nginx/fail2ban 的软件包与数据目录拦下。
// 记录时未安装的包（package-absent=）在依赖未装完时卸载，本次产生的数据/配置目录删除；安装前已有的包与目录不动。
function packageFixture(value, present) {
  writeFileSync(join(value.root, 'bin', 'dpkg-query'), `#!/bin/bash
echo "dpkg-query $*" >> "${value.root}/calls.log"
case " ${present.join(' ')} " in *" \${@: -1} "*) printf installed ;; *) exit 1 ;; esac
`, { mode: 0o755 })
  writeFileSync(join(value.root, 'bin', 'apt-get'), `#!/bin/bash\necho "apt-get $*" >> "${value.root}/calls.log"\n`, { mode: 0o755 })
}

test('cleanup purges the dependency packages and data this install added when the dependencies never finished', () => {
  const value = fixture()
  try {
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    value.file('etc/nginx/nginx.conf', 'operator', 0o644)
    packageFixture(value, ['nginx', 'nginx-common'])
    // main 在 ssh_guard_setup（装 fail2ban）之前取未安装的包与 /etc/fail2ban。
    const begin = value.run('control_install_state_prepare; control_install_state_begin; cat "$CONTROL_INSTALL_STATE_FILE"')
    assert.equal(begin.status, 0, begin.stderr)
    assert.match(begin.stdout, /^package-absent=redis-server$/m)
    assert.match(begin.stdout, /^package-absent=fail2ban$/m)
    assert.doesNotMatch(begin.stdout, /^package-absent=nginx$/m)
    assert.match(begin.stdout, new RegExp(`^path-absent=${join(value.root, 'etc/fail2ban').replace(/[/.]/g, '\\$&')}$`, 'm'))
    assert.match(begin.stdout, /preexisting=.*\/etc\/nginx$/m)
    // 装到一半：fail2ban、Redis、PostgreSQL、ClamAV 已装上，ClickHouse 未装上。
    for (const path of ['etc/fail2ban/jail.d/cdnca-sshd.local', 'etc/redis/redis.conf', 'var/lib/redis/dump.rdb',
      'var/lib/postgresql/17/main/PG_VERSION', 'etc/postgresql/17/main/postgresql.conf', 'etc/clamav/clamd.conf',
      'var/lib/clamav/main.cvd', 'etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf']) value.file(path, 'x', 0o644)
    packageFixture(value, ['nginx', 'nginx-common', 'fail2ban', 'redis-server', 'redis-tools', 'postgresql-17', 'clamav-daemon'])
    value.file('etc/systemd/system/cdnca-control-api.service', '[Unit]\n')
    // 宿主 bash 3.2 空数组在 set -u 下报 unbound（生产 bash ≥ 4.4 无此问题）：放一条 Redis include。
    value.file('etc/redis/redis.conf', `include ${join(value.root, 'etc/redis/cdnca-gateway/redis-gateway.conf')}\n`)
    const result = value.run('ASSUME_YES=true; cleanup_failed_run')
    assert.equal(result.status, 0, result.stderr)
    const purge = value.calls().split('\n').find((line) => line.startsWith('apt-get purge')) ?? ''
    for (const name of ['fail2ban', 'redis-server', 'redis-tools', 'postgresql-17', 'clamav-daemon']) assert.match(purge, new RegExp(` ${name}( |$)`), purge)
    assert.doesNotMatch(purge, / nginx( |$)/, 'preexisting package kept')
    for (const path of ['etc/fail2ban', 'etc/redis', 'var/lib/redis', 'var/lib/postgresql', 'etc/postgresql', 'etc/clamav', 'var/lib/clamav',
      'etc/systemd/system/clamav-daemon.socket.d']) assert.ok(!value.exists(path), `${path} kept`)
    assert.ok(value.exists('etc/nginx/nginx.conf'), 'preexisting nginx configuration removed')
    assert.match(result.stderr, /依赖软件包（本次安装装上、依赖未装完；卸载并清除配置，重装时重新安装）：redis-server/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('cleanup keeps the dependency packages once the dependency helper finished', () => {
  const value = fixture()
  try {
    mkdirSync(join(value.root, 'var/lib'), { recursive: true })
    packageFixture(value, [])
    assert.equal(value.run('control_install_state_prepare; control_install_state_begin').status, 0)
    writeFileSync(join(value.root, 'var/lib/cdnca-control-install/state'), 'step=dependencies_ready\n', { flag: 'a' })
    for (const path of ['var/lib/postgresql/17/main/PG_VERSION', 'etc/fail2ban/jail.d/cdnca-sshd.local']) value.file(path, 'x', 0o644)
    packageFixture(value, ['redis-server', 'postgresql-17', 'clickhouse-server', 'fail2ban'])
    value.file('etc/systemd/system/cdnca-control-api.service', '[Unit]\n')
    value.file('etc/redis/redis.conf', `include ${join(value.root, 'etc/redis/cdnca-gateway/redis-gateway.conf')}\n`)
    const result = value.run('ASSUME_YES=true; cleanup_failed_run')
    assert.equal(result.status, 0, result.stderr)
    assert.doesNotMatch(value.calls(), /apt-get purge/)
    for (const path of ['etc/redis/redis.conf', 'var/lib/postgresql/17/main/PG_VERSION', 'etc/fail2ban/jail.d/cdnca-sshd.local']) assert.ok(value.exists(path), `${path} removed`)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('cleanup removes the community edition state, units and the RustFS certificate hash links', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    for (const path of ['etc/cdnca-control/community/trusted-keys.json', 'etc/cdnca-control/entitlement-trusted-keys.json',
      'etc/systemd/system/cdnca-community-identity-refresh.service', 'etc/systemd/system/cdnca-community-identity-refresh.timer',
      'etc/cdnca-upgrade/api.env', 'var/lib/cdnca-upgrade/state', 'usr/local/cdnca-control/support/x']) value.file(path, 'x')
    const pem = value.file('etc/ssl/certs/cdnca-objectstore.pem', 'cert', 0o644)
    const link = join(value.root, 'etc/ssl/certs/0a1b2c3d.0')
    const other = join(value.root, 'etc/ssl/certs/9f8e7d6c.0')
    value.file('etc/ssl/certs/other.pem', 'other', 0o644)
    spawnSync('ln', ['-s', pem, link])
    spawnSync('ln', ['-s', join(value.root, 'etc/ssl/certs/other.pem'), other])
    const result = value.run('ASSUME_YES=true; cleanup_failed_run; assert_fresh_installation')
    assert.equal(result.status, 0, result.stderr)
    for (const path of ['etc/cdnca-control', 'etc/systemd/system/cdnca-community-identity-refresh.service',
      'etc/systemd/system/cdnca-community-identity-refresh.timer', 'etc/cdnca-upgrade', 'var/lib/cdnca-upgrade', 'usr/local/cdnca-control',
      'data/cdnca-native-root', 'etc/ssl/certs/cdnca-objectstore.pem']) assert.ok(!value.exists(path), `${path} kept`)
    assert.ok(!existsSync(link) && existsSync(other), 'only the objectstore hash link is removed')
    assert.match(value.calls(), /systemctl disable --now .*cdnca-community-identity-refresh\.timer/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})
