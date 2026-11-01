// install-control.sh「全新安装即可用」，并有 check 子命令覆盖对外合同（全新装完必须全过）：
//   - --origin-auth-secret-file 导入既有回源暗号（不再装完手工换）；
//   - install-control.sh check：单元、ready、signer-trust（启用时）、node-install-defaults、runtime-config.js、
//     安装汇总 0600、origin-auth 权限、升级 runner、安装记录完成。
import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].trimEnd().endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
const uid = String(process.getuid())

function withRoot(run) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-ih-control-'))
  try { return run(root) } finally { rmSync(root, { recursive: true, force: true }) }
}
function bash(root, names, script, env = {}) {
  return spawnSync('bash', ['-c', ['set -Eeuo pipefail', ...names.map(block), script].join('\n')], { encoding: 'utf8', timeout: 20000,
    env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`, ...env } })
}

const originNames = ['log', 'fail', 'origin_auth_check_import', 'origin_auth_import', 'origin_auth_secret']

test('--origin-auth-secret-file imports the existing key instead of generating one', () => withRoot((root) => {
  const key = 'Ab0_-'.repeat(8) + 'existing-cdn-rule-key'
  const file = join(root, 'cdn.secret')
  writeFileSync(file, `${key}\n`, { mode: 0o600 })
  const stub = `stat() { if [ "$2" = '%u' ]; then echo 0; else command stat -f '%Lp' "$3" 2>/dev/null || command stat -c '%a' "$3"; fi; }`
  const env = { ORIGIN_AUTH_IMPORT_FILE: file, ORIGIN_AUTH_SECRET_FILE: join(root, 'origin-auth.secret') }
  const ok = bash(root, originNames, `${stub}\norigin_auth_check_import "$ORIGIN_AUTH_IMPORT_FILE"; origin_auth_import; origin_auth_secret`, env)
  assert.equal(ok.status, 0, ok.stderr)
  assert.equal(ok.stdout, key)
  assert.equal(readFileSync(join(root, 'origin-auth.secret'), 'utf8'), key)
  assert.equal(statSync(join(root, 'origin-auth.secret')).mode & 0o777, 0o600)
  assert.ok(!ok.stderr.includes(key), 'the key must not be logged')
  chmodSync(file, 0o644)
  assert.match(bash(root, originNames, `${stub}\norigin_auth_check_import "$ORIGIN_AUTH_IMPORT_FILE"`, env).stderr, /0600/)
  writeFileSync(file, 'short\n', { mode: 0o600 })
  chmodSync(file, 0o600)
  assert.match(bash(root, originNames, `${stub}\norigin_auth_check_import "$ORIGIN_AUTH_IMPORT_FILE"`, env).stderr, /32–256/)
  assert.match(block('origin_auth_secret'), /^origin_auth_secret\(\) \{\n  local secret\n  ! declare -F origin_auth_import >\/dev\/null \|\| origin_auth_import\n/)
}))

// ---- check -------------------------------------------------------------------
const sha = (text) => createHash('sha256').update(text).digest('hex')
const trust = JSON.stringify({ document: { schema: 'cdnca.edge-signer-trust/v1', revision: 1, issued_at: '2026-10-31T00:00:00Z',
  trusted_keys: [{ key_id: 'cdnca-license-20261031', public_key_pem: 'PEM', usage: 'installation-ban' }], revoked_keys: [] },
  envelope: {}, signature: 'sig' })

// 一台“装好了”的主控（文件树 + systemctl/curl 桩）；mutate 修改某项后断言 check 失败。
function installed(root, mutate = () => {}) {
  const p = (...parts) => join(root, ...parts)
  for (const dir of ['bin', 'etc/plugin-runtime', 'data/downloads/edge-agent', 'state', 'run', 'units/cdnca-control-api.service.d']) mkdirSync(p(dir), { recursive: true })
  const upgradeTrust = '{"schema":"upgrade-trust"}'
  writeFileSync(p('data/downloads/edge-agent/upgrade-trust.json'), upgradeTrust)
  const digest = sha(upgradeTrust)
  const files = {
    'etc/control.env': 'PAYMENT_CHANNELS_NOTIFY_BASE=https://console.example\nLICENSE_SERVICE_URL=https://auth.example\nEDGE_SIGNER_TRUST_ENABLED=true\n',
    'etc/nginx.conf': `    include ${root}/etc/origin-auth.conf;\n        listen 443 ssl http2;\n`,
    'etc/origin-auth.conf': 'map ...',
    'etc/origin-auth.secret': 'x'.repeat(64),
    'summary.txt': 'summary',
    'state/state': 'schema=cdnca.control-install-state/v1\nstep=done\n',
    'run/status.json': '{"ready":true,"reason":"ready"}',
    'web/signer-trust.json': trust,
    'web/node-install-defaults': `upgrade_trust_sha256=${digest}\ngateway_enrollment_address=console.example:29402\ngateway_address=console.example:20407\ngateway_server_name=console.example\ndownload_fallback_origin=https://auth.example\n`,
    'web/runtime-config.js': `window.__CDNCA_GATEWAY_ADDRESS__ = "console.example:20407";\nwindow.__CDNCA_NODE_UPGRADE_TRUST_SHA256__ = "${digest}";\n`,
    'web/ready': 'ok', 'web/gateway-ready': 'ok', 'web/enroll': '400',
    'web/plugin-state': '{"status":"committed"}',
  }
  for (const [name, body] of Object.entries(files)) { mkdirSync(join(root, name, '..'), { recursive: true }); writeFileSync(p(name), body, { mode: 0o600 }) }
  writeFileSync(p('etc/plugin-runtime/client-state.json'), '{"status":"committed"}', { mode: 0o600 })
  for (const port of ['20407', '29402']) writeFileSync(p(`listening-${port}`), '')
  mutate(p)
  // systemctl：is-active 读 inactive-<单元> 标记；show -p EnvironmentFiles 返回 drop-in 是否被加载。
  writeFileSync(p('bin/systemctl'), `#!/usr/bin/env bash
case "$1" in
  is-active) shift; [ "$1" = --quiet ] && shift; [ ! -e "${root}/inactive-$1" ] ;;
  show) if [ -e "${root}/units/cdnca-control-api.service.d/60-optional.conf" ]; then echo "${root}/etc/control.env (ignore_errors=no) ${root}/etc/optional.env (ignore_errors=no)"; else echo "${root}/etc/control.env (ignore_errors=no)"; fi ;;
  *) exit 0 ;;
esac
`, { mode: 0o755 })
  // ss：listening-<端口> 标记存在即监听。
  writeFileSync(p('bin/ss'), `#!/usr/bin/env bash
for a; do case "$a" in *sport*) port=\${a##*:}; esac; done
[ -e "${root}/listening-$port" ] && echo "LISTEN 0 4096 0.0.0.0:$port"
exit 0
`, { mode: 0o755 })
  // curl：按 URL 末段返回 web/ 下同名文件；不存在 = HTTP 失败。
  writeFileSync(p('bin/curl'), `#!/usr/bin/env bash
for last; do :; done
case "$last" in
  */health/ready) f=${root}/web/$( [[ "$last" == *8082* ]] && echo gateway-ready || echo ready ) ;;
  *) f=${root}/web/\${last##*/} ;;
esac
case "$*" in *%{http_code}*) [ -f "$f" ] && cat "$f" || printf 000; exit 0 ;; esac
[ -f "$f" ] || exit 22
cat "$f"
`, { mode: 0o755 })
  const env = { CONFIG_DIR: p('etc'), DATA_DIR: p('data'), DOWNLOAD_DIR: p('data/downloads'), NGINX_CONF: p('etc/nginx.conf'),
    CONTROL_SUMMARY_FILE: p('summary.txt'), CONTROL_INSTALL_STATE_FILE: p('state/state'), OPTIONAL_ENV_FILE: p('etc/optional.env'),
    OPTIONAL_DROPIN: p('units/cdnca-control-api.service.d/60-optional.conf'), ORIGIN_AUTH_CONF: p('etc/origin-auth.conf'),
    ORIGIN_AUTH_SECRET_FILE: p('etc/origin-auth.secret'), PLUGIN_RUNTIME_DIR: p('etc/plugin-runtime'), UPGRADE_STATUS_FILE: p('run/status.json'),
    CHECK_OWNER_UID: uid, SERVICE_NAME: 'cdnca-control-api', GATEWAY_SERVICE_NAME: 'cdnca-agent-gateway',
    NATS_SERVICE_NAME: 'cdnca-control-nats', WEB_SERVICE_NAME: 'cdnca-control-web', INSTALL_LANG: 'zh' }
  return bash(root, ['log', 'warn', 'fail', 'file_owner_mode', 'check_env_value', 'check_fetch', 'check_gateway_endpoints_value', 'check_node_install_defaults_lines', 'check_port_listening', 'check_gateway_entry', 'check_main'], 'check_main', env)
}

test('check passes on a complete fresh installation', () => withRoot((root) => {
  const result = installed(root)
  assert.equal(result.status, 0, result.stdout + result.stderr)
  const out = result.stdout + result.stderr
  for (const item of ['cdnca-control-api', 'cdnca-agent-gateway', 'control-api /health/ready', 'agent-gateway /health/ready',
    'signer-trust.json', 'installation-ban', 'node-install-defaults', 'runtime-config.js', '安装汇总', '回源', '升级 runner', '安装记录']) {
    assert.ok(out.includes(item), `check output lacks ${item}\n${out}`)
  }
  assert.match(out, /失败 0/)
}))

test('check fails on each missing piece of the fresh-install contract', () => {
  const cases = [
    ['inactive unit', (p) => writeFileSync(p('inactive-cdnca-control-web'), ''), /cdnca-control-web/],
    ['control-api not ready', (p) => rmSync(p('web/ready')), /control-api \/health\/ready/],
    ['gateway not ready', (p) => rmSync(p('web/gateway-ready')), /agent-gateway \/health\/ready/],
    ['no signer trust', (p) => rmSync(p('web/signer-trust.json')), /signer-trust\.json/],
    ['trust without installation-ban', (p) => writeFileSync(p('web/signer-trust.json'), trust.replace('"usage":"installation-ban"', '"usage":"other"')), /installation-ban/],
    ['stale defaults pin', (p) => writeFileSync(p('web/node-install-defaults'), readFileSync(p('web/node-install-defaults'), 'utf8').replace(/=[0-9a-f]{64}/, '=' + 'a'.repeat(64))), /node-install-defaults/],
    ['unknown defaults key', (p) => writeFileSync(p('web/node-install-defaults'), readFileSync(p('web/node-install-defaults'), 'utf8') + 'bogus=1\n'), /node-install-defaults/],
    ['no runtime-config', (p) => rmSync(p('web/runtime-config.js')), /runtime-config\.js/],
    ['summary readable', (p) => chmodSync(p('summary.txt'), 0o644), /安装汇总/],
    ['summary missing', (p) => rmSync(p('summary.txt')), /安装汇总/],
    ['origin-auth conf readable', (p) => chmodSync(p('etc/origin-auth.conf'), 0o644), /origin-auth\.conf/],
    ['origin-auth secret readable', (p) => chmodSync(p('etc/origin-auth.secret'), 0o640), /origin-auth\.secret/],
    ['runner not ready', (p) => writeFileSync(p('run/status.json'), '{"ready":false,"reason":"starting"}'), /升级 runner/],
    ['install unfinished', (p) => writeFileSync(p('state/state'), 'schema=cdnca.control-install-state/v1\n'), /安装记录/],
  ]
  for (const [name, mutate, message] of cases) withRoot((root) => {
    const result = installed(root, mutate)
    assert.notEqual(result.status, 0, `${name} should fail`)
    assert.match(result.stdout + result.stderr, message, name)
  })
})

test('check accepts installs without origin auth or signer trust (community build)', () => withRoot((root) => {
  const result = installed(root, (p) => {
    rmSync(p('etc/origin-auth.conf')); rmSync(p('etc/origin-auth.secret'))
    writeFileSync(p('etc/nginx.conf'), '        listen 443 ssl http2;\n')
    writeFileSync(p('etc/control.env'), 'PAYMENT_CHANNELS_NOTIFY_BASE=https://console.example\nEDGE_SIGNER_TRUST_ENABLED=false\n', { mode: 0o600 })
    rmSync(p('web/signer-trust.json'))
  })
  assert.equal(result.status, 0, result.stdout + result.stderr)
}))

test('main dispatches the check subcommand before the install path and usage documents it', () => {
  assert.match(block('parse_args'), /^parse_args\(\) \{\n  # [^\n]*\n  \[ "\$\{1:-\}" != check \] \|\| \{ shift; check_main "\$@"; exit \$\?; \}\n/)
  assert.match(block('usage'), /install-control\.sh check/)
  assert.match(block('control_install_summary'), /install-control\.sh check/)
})

// ---- Q20：节点 WebSocket 入口（CDN 模式默认 ws，node-install-defaults 写 transport/tunnel_host/endpoints，:443） ----
const nodeInstaller = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8').replace(/^main "\$@"\s*$/m, '')
function nodeDefaults(env) {
  return withRoot((root) => {
    mkdirSync(join(root, 'downloads'))
    const result = bash(root, ['fail', 'gateway_transport_resolve', 'gateway_ws_entry_address', 'write_node_install_defaults'],
      'gateway_transport_resolve; write_node_install_defaults', { TEMP_DIR: root, DOWNLOAD_DIR: join(root, 'downloads'),
        GATEWAY_HOST: 'gw.example', GATEWAY_ENROLLMENT_PORT: '29402', GATEWAY_AGENT_PORT: '20407', LICENSING_SERVER: 'https://auth.example',
        UPGRADE_TRUST_SHA256: 'c'.repeat(64), GATEWAY_TRANSPORT: '', GATEWAY_TUNNEL_HOST: '', ORIGIN_AUTH: 'false', REAL_IP_HEADER_SET: 'false', ...env })
    return { result, body: result.status === 0 ? readFileSync(join(root, 'downloads/node-install-defaults'), 'utf8') : '' }
  })
}
const loadDefaults = (body) => spawnSync('bash', ['-c', `fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
printf '#!/usr/bin/env bash\\nprintf "%%s" "$DEFAULTS_BODY"\\n' >"$fake/curl"; chmod +x "$fake/curl"; PATH="$fake:$PATH"
${nodeInstaller}
parse_args --control-plane https://control.example --registration-key-stdin
load_console_defaults
printf '%s|%s|%s|%s|%s|%s' "$GATEWAY_ENROLLMENT_ADDRESS" "$GATEWAY_ADDRESS" "$GATEWAY_SERVER_NAME" "\${GATEWAY_TRANSPORT:-grpc}" "$GATEWAY_TUNNEL_HOST" "$GATEWAY_ENDPOINTS"`],
{ encoding: 'utf8', env: { ...process.env, DEFAULTS_BODY: body } })

test('CDN mode (--origin-auth / --real-ip-header) defaults nodes to ws on :443 with the direct ports as fallback', () => {
  for (const env of [{ ORIGIN_AUTH: 'true' }, { REAL_IP_HEADER_SET: 'true' }, { GATEWAY_TRANSPORT: 'ws' }]) {
    const { result, body } = nodeDefaults(env)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(body, [`upgrade_trust_sha256=${'c'.repeat(64)}`, 'gateway_enrollment_address=gw.example:443', 'gateway_address=gw.example:443',
      'gateway_server_name=gw.example', 'gateway_transport=ws', 'gateway_tunnel_host=gw.example',
      'gateway_endpoints=gw.example:20407|gw.example|grpc', 'download_fallback_origin=https://auth.example', ''].join('\n'), JSON.stringify(env))
    // macOS bash 3.2 的正则库拒绝 install-node.sh 的 gateway_endpoints 校验式（Linux bash 5 接受，见 check_gateway_endpoints_value 注释）。
    if (process.platform !== 'darwin') {
      const loaded = loadDefaults(body)
      assert.equal(loaded.status, 0, loaded.stderr)
      assert.equal(loaded.stdout, 'gw.example:443|gw.example:443|gw.example|ws|gw.example|gw.example:20407|gw.example|grpc')
    }
  }
})

test('direct mode and --gateway-transport tcp keep the two Gateway ports and no ws lines', () => {
  for (const env of [{}, { ORIGIN_AUTH: 'true', GATEWAY_TRANSPORT: 'tcp' }]) {
    const { result, body } = nodeDefaults(env)
    assert.equal(result.status, 0, result.stderr)
    assert.doesNotMatch(body, /gateway_transport|gateway_tunnel_host|gateway_endpoints/)
    assert.match(body, /^gateway_address=gw\.example:20407$/m)
    assert.equal(loadDefaults(body).stdout, 'gw.example:29402|gw.example:20407|gw.example|grpc||')
  }
})

test('--gateway-tunnel-host sets the outer CDN host; invalid combinations are refused', () => {
  const { body } = nodeDefaults({ GATEWAY_TRANSPORT: 'ws', GATEWAY_TUNNEL_HOST: 'edge.cdn.example' })
  assert.match(body, /^gateway_tunnel_host=edge\.cdn\.example$/m)
  assert.match(body, /^gateway_address=edge\.cdn\.example:443$/m)
  assert.match(body, /^gateway_server_name=gw\.example$/m)
  for (const env of [{ GATEWAY_TRANSPORT: 'quic' }, { GATEWAY_TRANSPORT: 'tcp', GATEWAY_TUNNEL_HOST: 'x.example' }, { GATEWAY_TRANSPORT: 'ws', GATEWAY_TUNNEL_HOST: 'bad host' }]) {
    assert.notEqual(nodeDefaults(env).result.status, 0, JSON.stringify(env))
  }
  const parse = block('parse_args')
  for (const flag of ['--gateway-transport', '--gateway-tunnel-host']) {
    assert.ok(parse.includes(`${flag})`), flag)
    assert.ok(block('usage').includes(flag), flag)
  }
  assert.match(parse, /--real-ip-header\) need_value "\$@"; REAL_IP_HEADER=\$2; REAL_IP_HEADER_SET=true;/)
})

test('a ws install publishes the ws entry to control-api (one writer keeps node-install-defaults in step)', () => {
  const env = block('local_gateway_environment')
  assert.match(env, /CDNCA_GATEWAY_LOCAL_ADDRESS=/)
  assert.ok(source.includes('seed_gateway_ws_entrypoint'), 'installer must seed the ws entry point')
  assert.match(block('main'), /bootstrap_system_configuration\n  seed_gateway_ws_entrypoint\n/)
})

const wsDefaults = (p) => writeFileSync(p('web/node-install-defaults'), readFileSync(p('web/node-install-defaults'), 'utf8')
  .replace(/gateway_enrollment_address=.*\ngateway_address=.*\n/, 'gateway_enrollment_address=console.example:443\ngateway_address=console.example:443\n')
  .replace('gateway_server_name=console.example\n', 'gateway_server_name=console.example\ngateway_transport=ws\ngateway_tunnel_host=console.example\ngateway_endpoints=console.example:20407|console.example|grpc\n'))
test('check verifies the node gateway entry: direct ports listen, ws reaches /agent/v1/enroll on the console port', () => {
  withRoot((root) => {
    const direct = installed(root)
    assert.equal(direct.status, 0, direct.stdout + direct.stderr)
    assert.match(direct.stdout, /OK   节点网关入口可用：grpc console\.example:20407/)
  })
  withRoot((root) => {
    const ws = installed(root, (p) => { wsDefaults(p);})
    assert.equal(ws.status, 0, ws.stdout + ws.stderr)
    assert.match(ws.stdout, /OK   节点网关入口可用：ws console\.example:443/)
  })
  for (const [name, mutate] of [
    ['ws not proxied', (p) => { wsDefaults(p); writeFileSync(p('web/enroll'), '404') }],
    ['ws fallback port down', (p) => { wsDefaults(p); rmSync(p('listening-20407')) }],
    ['direct port down', (p) => rmSync(p('listening-20407'))],
  ]) withRoot((root) => {
    const result = installed(root, mutate)
    assert.notEqual(result.status, 0, name)
    assert.match(result.stdout, /FAIL 节点网关入口不可用/, name)
  })
})

test('the console nginx proxies /agent/v1/ to the local Gateway channel port', () => {
  assert.match(source, /location \^~ \/agent\/v1\/ \{\n[\s\S]*?proxy_set_header Upgrade \\\$http_upgrade;[\s\S]*?proxy_pass https:\/\/127\.0\.0\.1:\$\{GATEWAY_AGENT_PORT:-20407\};\n        \}/)
})

// ---- 安装器与签名包配套：ws 安装要调 control-api gateway-entrypoint ensure；旧签名包没有该子命令时，
// 在激活（消耗激活码）之前明确报「版本不配套」，而不是装到第 10 步才报模糊错误。 ----
const pairNames = ['msg', 'fail', 'assert_control_binary_matches_installer']
function pairing(root, binary, vars) {
  mkdirSync(join(root, 'bin'), { recursive: true })
  const path = join(root, 'bin/control-api')
  writeFileSync(path, `#!/usr/bin/env bash\n${binary}\n`)
  chmodSync(path, 0o755)
  return bash(root, pairNames, 'assert_control_binary_matches_installer; echo ok', { CONTROL_BINARY: path, ...vars })
}
const newBinary = 'case "$1" in gateway-entrypoint) echo "level=ERROR msg=\\"control-api command failed\\" error=\\"usage: control-api gateway-entrypoint ensure --address HOST:PORT\\"" >&2; exit 1 ;; esac; exit 0'
const oldBinary = 'echo "level=ERROR msg=\\"control-api command failed\\" error=\\"usage: control-api serve | migrate up|down\\"" >&2; exit 1'
test('ws install refuses an older signed control-api without gateway-entrypoint before activation', () => withRoot((root) => {
  const zh = pairing(root, oldBinary, { GATEWAY_TRANSPORT: 'ws', INSTALL_LANG: 'zh' })
  assert.notEqual(zh.status, 0)
  assert.match(zh.stderr, /安装器与安装包版本不配套，请用同一版本的安装命令/)
  assert.match(zh.stderr, /gateway-entrypoint/)
  const en = pairing(root, oldBinary, { GATEWAY_TRANSPORT: 'ws', INSTALL_LANG: 'en' })
  assert.notEqual(en.status, 0)
  assert.match(en.stderr, /installer and package versions do not match/)
  assert.equal(pairing(root, newBinary, { GATEWAY_TRANSPORT: 'ws' }).stdout.trim(), 'ok')
  assert.equal(pairing(root, oldBinary, { GATEWAY_TRANSPORT: 'tcp' }).stdout.trim(), 'ok')
  const main = block('main')
  assert.match(main, /prepare_native_baseline\n  assert_control_binary_matches_installer\n/)
  assert.ok(main.indexOf('assert_control_binary_matches_installer') < main.indexOf('\n  install_community\n'))
}))
