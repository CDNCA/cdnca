// install-control.sh enable-gateway-access: an installed --mode all console
// opens standalone Gateway access in place. Real installer functions, real
// openssl/jq; systemctl, redis-cli, nft, curl and flock are recording doubles.
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
const constants = source.split('\n').filter((line) => /^readonly (CONTROL_INTERNAL_REMOTE_PORT|NATS_GATEWAY_WS_PORT|REDIS_GATEWAY_TLS_PORT|SERVICE_NAME|GATEWAY_SERVICE_NAME|NATS_SERVICE_NAME)=/.test(line)).join('\n')
const real = ['fail', 'warn', 'log', 'need_value', 'valid_host', 'host_san', 'issue_certificate', 'remote_gateway_access',
  'generate_gateway_access_secrets', 'nats_gateway_permissions', 'write_nats_config', 'configure_redis_gateway_access',
  'control_internal_server_san', 'gateway_access_environment', 'gateway_access_parse_args', 'gateway_access_env_value',
  'gateway_access_control_domain', 'gateway_access_lock', 'gateway_access_load_secrets', 'gateway_access_redis_cli',
  'gateway_access_backup', 'gateway_access_changed', 'gateway_access_restore', 'gateway_access_certificate_covers',
  'gateway_access_write', 'gateway_access_restart', 'gateway_access_services_ready', 'gateway_access_ready',
  'gateway_access_wait', 'gateway_access_rollback', 'gateway_access_on_exit']
// Non-root test run: only the EUID gate is lifted (asserted below).
const main = block('gateway_access_main').replace(`  [ "$EUID" -eq 0 ] || fail 'run this installer as root'\n`, '')

function host() {
  const d = mkdtempSync(join(tmpdir(), 'gwaccess-'))
  for (const dir of ['etc', 'pki', 'units', 'redis', 'tmp', 'data']) mkdirSync(join(d, dir))
  const sh = (cmd) => spawnSync('bash', ['-c', cmd], { cwd: d, encoding: 'utf8' })
  // Installation PKI as --mode all leaves it: control-internal-server only names localhost.
  assert.equal(sh([
    'openssl req -x509 -newkey rsa:2048 -nodes -keyout pki/root-ca-key.pem -out pki/root-ca-cert.pem -subj /CN=root -days 2 2>/dev/null',
    'cp pki/root-ca-cert.pem pki/gateway-client-ca-cert.pem',
    'openssl req -newkey rsa:2048 -nodes -keyout pki/control-internal-server-key.pem -out tmp/c.csr -subj /CN=localhost 2>/dev/null',
    "printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\\n' >tmp/c.ext",
    'openssl x509 -req -in tmp/c.csr -CA pki/root-ca-cert.pem -CAkey pki/root-ca-key.pem -CAcreateserial -extfile tmp/c.ext -out pki/control-internal-server.pem -days 2 2>/dev/null',
    'rm -f tmp/c.csr tmp/c.ext pki/*.srl'].join(' && ')).status, 0)
  writeFileSync(join(d, 'etc/control.env'), ['DATABASE_URL=postgres://x', 'REDIS_URL=redis://127.0.0.1:6379/0',
    'EDGE_DEPLOYMENT_NATS_URL=nats://127.0.0.1:4222', 'NODE_PRESENCE_REDIS_URL=redis://127.0.0.1:6379/0',
    'PAYMENT_CHANNELS_NOTIFY_BASE=https://control.example.com:8443', ''].join('\n'))
  writeFileSync(join(d, 'etc/nats.json'), '{"host":"127.0.0.1","port":4222}\n')
  writeFileSync(join(d, 'redis/redis.conf'), 'bind 127.0.0.1\nport 6379\n')
  return d
}

// FAIL=<stage> makes that double fail: restart (control-api restart) or ready (health stays down).
function run(d, env = {}, args = '') {
  const script = ['set -Eeuo pipefail', constants,
    `D=${d}`, 'CONFIG_DIR=$D/etc PKI_DIR=$D/pki TEMP_DIR=$D/tmp SYSTEMD_UNIT_DIR=$D/units',
    'GATEWAY_ACCESS_SECRETS=$D/etc/gateway-access.secrets GATEWAY_ACCESS_CONTROL_ENV=$D/etc/gateway-access.env',
    'GATEWAY_ACCESS_LOCAL_ENV=$D/etc/gateway-access-local.env GATEWAY_ACCESS_SYNC=$D/units/sync GATEWAY_ACCESS_LOCK=$D/lock',
    'GATEWAY_ACCESS_FILE=$D/data/allowed-ips NATS_DATA_DIR=$D/data/nats NATS_CLI_BIN=true',
    'GATEWAY_ACCESS_WAIT=2 GATEWAY_ACCESS_REDIS_CLI=redis-cli GATEWAY_ACCESS_BACKUP="" GATEWAY_ACCESS_TOUCHED=false GATEWAY_ACCESS_FIREWALL_NEW=false',
    'GATEWAY_ACCESS_SAVED=() CONTROL_DOMAIN="" REDIS_URL=redis://127.0.0.1:6379/0 INSTALL_MODE=all',
    `FAIL=${env.FAIL ?? ''}`,
    ...real.map(block),
    // Doubles after the real blocks: one-line helpers above make block() over-capture.
    'usage() { :; }; cleanup() { :; }; sleep() { :; }; flock() { :; }; chown() { :; }; restorecon() { :; }',
    'calls() { printf "%s\\n" "$*" >>$D/calls; }',
    'nft() { calls nft "$@"; cat >/dev/null; }',
    // Redis needs the password once restarted with the include that sets it.
    'redis-cli() { local need; need=$(cat $D/redis-required 2>/dev/null || true)',
    '  if [ -n "$need" ] && [ "${REDISCLI_AUTH:-}" != "$need" ]; then echo "NOAUTH Authentication required."; return 0; fi',
    '  case "$*" in *PING*) echo PONG ;; *INFO*) printf "config_file:%s\\r\\n" $D/redis/redis.conf ;; esac; }',
    'systemctl() { calls systemctl "$@"; [ "$1" = restart ] || return 0',
    '  case "$2" in redis-server) awk \'$1 == "requirepass" {print $2}\' $D/redis/cdnca-gateway/redis-gateway.conf 2>/dev/null >$D/redis-required || true',
    '    grep -q "include $D/redis/cdnca-gateway/redis-gateway.conf" $D/redis/redis.conf || : >$D/redis-required ;;',
    '  cdnca-control-api) [ "$FAIL" != restart ] || return 1',
    '    if [ -f $D/units/cdnca-control-api.service.d/60-gateway-access.conf ]; then : >$D/listening; else rm -f $D/listening; fi ;; esac; }',
    'curl() { [ "$FAIL" != ready ] || [ ! -f $D/listening ]; }',
    'preflight_listening_ports() { [ ! -f $D/listening ] || printf "%s\\n" 22 4223 6380 9446; }',
    'setup_gateway_access_firewall() { calls firewall; printf "unit\\n" >$SYSTEMD_UNIT_DIR/cdnca-gateway-access.service; nft -f - </dev/null; }',
    main,
    'trap cleanup EXIT', `gateway_access_main ${args}`].join('\n')
  return spawnSync('bash', ['-c', script], { encoding: 'utf8', timeout: 60000 })
}
const read = (d, path) => (existsSync(join(d, path)) ? readFileSync(join(d, path), 'utf8') : null)
const restarts = (d) => (read(d, 'calls') ?? '').split('\n').filter((line) => line.startsWith('systemctl restart'))

test('subcommand is dispatched before argument parsing and gated on root', () => {
  assert.match(block('main'), /migrate_main "\$@"; return; \}\n {2}\[ "\$\{1:-\}" != enable-gateway-access \] \|\| \{ shift; gateway_access_main "\$@"; return; \}\n {2}\[ "\$\{1:-\}" != --cleanup-failed \] \|\| \{ shift; cleanup_failed_main "\$@"; return; \}\n {2}! gateway_mode_requested/)
  assert.match(block('gateway_access_main'), /\[ "\$EUID" -eq 0 \] \|\| fail 'run this installer as root'/)
  assert.match(block('usage'), /install-control\.sh enable-gateway-access \[--domain 主控域名\]/)
  // control.env is pinned by runtime-receipt.json: the subcommand never writes it.
  for (const name of real.filter((n) => n.startsWith('gateway_access_')).concat('gateway_access_main')) {
    assert.doesNotMatch(block(name), />>?\s*"?\$\{?CONFIG_DIR\}?\/control\.env/, name)
  }
})

test('first run opens access like --mode control and keeps loopback consumers working', () => {
  const d = host()
  try {
    const before = read(d, 'etc/control.env')
    const result = run(d)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /已开启独立网关接入/)
    assert.equal(read(d, 'etc/control.env'), before)
    const secrets = Object.fromEntries(read(d, 'etc/gateway-access.secrets').trim().split('\n').map((l) => l.split('=')))
    assert.deepEqual(Object.keys(secrets).sort(), ['NATS_GATEWAY_PASSWORD', 'NATS_LOCAL_PASSWORD', 'REDIS_DEFAULT_PASSWORD', 'REDIS_GATEWAY_PASSWORD'])
    const env = Object.fromEntries(read(d, 'etc/gateway-access.env').trim().split('\n').map((l) => l.split(/=(.*)/s).slice(0, 2)))
    const redis = `redis://:${secrets.REDIS_DEFAULT_PASSWORD}@127.0.0.1:6379/0`
    assert.equal(env.REDIS_URL, redis)
    assert.equal(env.NODE_PRESENCE_REDIS_URL, redis)
    assert.equal(env.CDNCA_CONTROL_INTERNAL_REMOTE_ADDR, '0.0.0.0:9446')
    assert.equal(env.CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS, 'control.example.com:9446')
    assert.equal(env.CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME, 'control.example.com')
    assert.equal(env.CDNCA_GATEWAY_REMOTE_REDIS_URL, `rediss://cdnca-gateway:${secrets.REDIS_GATEWAY_PASSWORD}@control.example.com:6380/0`)
    assert.equal(env.CDNCA_GATEWAY_REMOTE_NATS_URL, `wss://cdnca-gateway:${secrets.NATS_GATEWAY_PASSWORD}@control.example.com:4223`)
    assert.equal(read(d, 'etc/gateway-access-local.env'), `CDNCA_REDIS_URL=${redis}\n`)
    assert.equal(read(d, 'units/cdnca-control-api.service.d/60-gateway-access.conf'), `[Service]\nEnvironmentFile=${d}/etc/gateway-access.env\n`)
    assert.equal(read(d, 'units/cdnca-agent-gateway.service.d/60-gateway-access.conf'), `[Service]\nEnvironmentFile=${d}/etc/gateway-access-local.env\n`)
    const nats = JSON.parse(read(d, 'etc/nats.json'))
    assert.deepEqual([nats.host, nats.port, nats.no_auth_user, nats.websocket.port], ['127.0.0.1', 4222, 'local', 4223])
    assert.ok(nats.authorization.users.some((u) => u.user === 'cdnca-gateway' && u.password === secrets.NATS_GATEWAY_PASSWORD))
    assert.match(read(d, 'redis/redis.conf'), new RegExp(`\ninclude ${d}/redis/cdnca-gateway/redis-gateway\\.conf\n$`))
    assert.match(read(d, 'redis/cdnca-gateway/redis-gateway.conf'), new RegExp(`requirepass ${secrets.REDIS_DEFAULT_PASSWORD}\ntls-port 6380`))
    const san = spawnSync('openssl', ['x509', '-in', join(d, 'pki/control-internal-server.pem'), '-noout', '-ext', 'subjectAltName'], { encoding: 'utf8' }).stdout
    assert.match(san, /DNS:localhost, IP Address:127\.0\.0\.1, DNS:control\.example\.com/)
    assert.deepEqual(restarts(d), ['systemctl restart redis-server', 'systemctl restart cdnca-control-nats',
      'systemctl restart cdnca-control-api', 'systemctl restart cdnca-agent-gateway'])
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('a rerun is idempotent: same secrets and files, no restart', () => {
  const d = host()
  try {
    assert.equal(run(d).status, 0)
    const files = ['etc/gateway-access.secrets', 'etc/gateway-access.env', 'etc/nats.json', 'redis/redis.conf', 'pki/control-internal-server.pem']
    const first = files.map((f) => read(d, f))
    rmSync(join(d, 'calls'))
    const again = run(d)
    assert.equal(again.status, 0, again.stderr)
    assert.match(again.stdout, /已经开启，配置没有变化，未重启任何服务/)
    assert.deepEqual(files.map((f) => read(d, f)), first)
    assert.deepEqual(restarts(d), [])
    assert.equal((read(d, 'redis/redis.conf').match(/^include /gm) ?? []).length, 1)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

for (const stage of ['restart', 'ready']) {
  test(`failure at ${stage} restores every file and restarts on the original configuration`, () => {
    const d = host()
    try {
      const files = ['etc/control.env', 'etc/nats.json', 'redis/redis.conf', 'pki/control-internal-server.pem', 'pki/control-internal-server-key.pem']
      const before = files.map((f) => read(d, f))
      const result = run(d, { FAIL: stage })
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, /正在恢复原配置/)
      assert.deepEqual(files.map((f) => read(d, f)), before)
      for (const gone of ['etc/gateway-access.secrets', 'etc/gateway-access.env', 'etc/gateway-access-local.env', 'redis/cdnca-gateway',
        'units/cdnca-control-api.service.d/60-gateway-access.conf', 'units/cdnca-agent-gateway.service.d/60-gateway-access.conf',
        'units/cdnca-gateway-access.service']) {
        assert.equal(existsSync(join(d, gone)), false, gone)
      }
      assert.match(read(d, 'calls'), /systemctl disable --now cdnca-gateway-access\.path cdnca-gateway-access\.service/)
      assert.match(read(d, 'calls'), /nft delete table inet cdnca_gateway_access/)
      // Rollback restarted Redis without the password: loopback clients are back to the original URL.
      assert.equal(read(d, 'redis-required'), '')
      assert.equal(restarts(d).filter((line) => line === 'systemctl restart cdnca-control-api').length, 2)
    } finally { rmSync(d, { recursive: true, force: true }) }
  })
}

test('refuses what it cannot open safely, before changing anything', () => {
  const cases = [
    ['REDIS_URL=redis://127.0.0.1:6379/0', 'REDIS_URL=redis://db.example.com:6379/0', /only the local Redis/],
    ['PAYMENT_CHANNELS_NOTIFY_BASE=https://control.example.com:8443', 'PAYMENT_CHANNELS_NOTIFY_BASE=', /pass --domain/],
  ]
  for (const [from, to, message] of cases) {
    const d = host()
    try {
      writeFileSync(join(d, 'etc/control.env'), read(d, 'etc/control.env').replace(from, to))
      const result = run(d)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, message)
      assert.equal(existsSync(join(d, 'etc/gateway-access.env')), false)
      assert.equal(read(d, 'calls'), null)
    } finally { rmSync(d, { recursive: true, force: true }) }
  }
  const d = host()
  try {
    writeFileSync(join(d, 'etc/control.env'), `${read(d, 'etc/control.env')}CDNCA_CONTROL_INTERNAL_REMOTE_ADDR=0.0.0.0:9446\n`)
    const result = run(d)
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /安装时已开放独立网关接入/)
    assert.equal(read(d, 'calls'), null)
  } finally { rmSync(d, { recursive: true, force: true }) }
})

test('--domain overrides the domain from control.env, IPv6 brackets are stripped', () => {
  const d = host()
  try {
    const result = run(d, {}, '--domain GW-Control.Example.NET')
    assert.equal(result.status, 0, result.stderr)
    assert.match(read(d, 'etc/gateway-access.env'), /^CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME=gw-control\.example\.net$/m)
  } finally { rmSync(d, { recursive: true, force: true }) }
  const v6 = host()
  try {
    writeFileSync(join(v6, 'etc/control.env'), read(v6, 'etc/control.env').replace('https://control.example.com:8443', 'https://[2001:db8::5]:8443'))
    const result = run(v6)
    assert.equal(result.status, 0, result.stderr)
    assert.match(read(v6, 'etc/gateway-access.env'), /^CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS=\[2001:db8::5\]:9446$/m)
  } finally { rmSync(v6, { recursive: true, force: true }) }
})
