// fix-btenv：主控与宝塔面板共存。--env auto|bt|plain，宝塔模式下不动宝塔的
// nginx/面板端口，我方 Web 改监听 127.0.0.1:<替代端口>，依赖端口被占时换端口，
// 预检输出中文清单，--bt-proxy 自动写入宝塔站点反向代理（备份、nginx -t、失败回滚）。
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const library = new URL('../scripts/lib/install-preflight.sh', import.meta.url).pathname
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
const reserved = source.match(/^readonly NATIVE_RESERVED_PORTS=.*$/m)[0]
const btFunctions = ['bt_detect', 'resolve_install_env', 'bt_port_free', 'bt_pick_port', 'plan_install_ports',
  'control_preflight_ports', 'bt_check_site_certificate', 'bt_web_server', 'bt_proxy_apache_config', 'bt_proxy_openlitespeed_config',
  'bt_preflight_records', 'bt_proxy_config', 'bt_install_proxy', 'bt_report']

// /proc/net/tcp 行：0.0.0.0:<端口>，状态 0A（LISTEN）。
const tcpRows = (ports) => '  sl  local_address rem_address   st\n' + ports.map((port, index) =>
  `   ${index}: 00000000:${port.toString(16).toUpperCase().padStart(4, '0')} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n`).join('')

function fixture({ panel = true, version = '9.2.0', panelPort = '8888', listen = [], btCommand = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-btenv-'))
  mkdirSync(join(root, 'proc/net'), { recursive: true })
  mkdirSync(join(root, 'bin'))
  writeFileSync(join(root, 'proc/net/tcp'), tcpRows(listen))
  writeFileSync(join(root, 'proc/net/tcp6'), tcpRows([]))
  if (panel) {
    mkdirSync(join(root, 'www/server/panel/data'), { recursive: true })
    mkdirSync(join(root, 'www/server/panel/class'), { recursive: true })
    writeFileSync(join(root, 'www/server/panel/data/port.pl'), `${panelPort}\n`)
    if (version) writeFileSync(join(root, 'www/server/panel/class/common.py'), `import os\n    g.version = '${version}'\n`)
  }
  if (btCommand) { writeFileSync(join(root, 'bin/bt'), '#!/bin/sh\nexit 0\n'); chmodSync(join(root, 'bin/bt'), 0o755) }
  return root
}

// 安装器顶部的依赖端口默认值（PG_PORT=5432 等）原样取用。
const defaults = Object.fromEntries([...source.matchAll(/^((?:PG|REDIS|CH_[A-Z]+)_PORT)=([0-9]+)$/gm)].map((match) => [match[1], match[2]]))
assert.equal(Object.keys(defaults).length, 7)

function run(root, body, env = {}) {
  const script = ['set -Eeuo pipefail', `source ${JSON.stringify(library)}`, block('log'), block('warn'), block('fail'),
    block('valid_port'), reserved, ...btFunctions.map(block), body].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', timeout: 20000,
    env: { PATH: `${join(root, 'bin')}:/usr/bin:/bin:/usr/sbin:/sbin`, PREFLIGHT_ROOT: root, BT_ROOT: root, HOME: root,
      INSTALL_ENV: 'auto', WEB_PORT: '', MASTER_PORT: '443', GATEWAY_ENROLLMENT_PORT: '21443', GATEWAY_AGENT_PORT: '21444',
      SKIP_DEPENDENCIES: 'false', CONTROL_DOMAIN: 'cdnca.com', BT_SITE: '', BT_PROXY: 'false', CONFIG_DIR: root,
      DOWNLOAD_DIR: '/var/lib/cdnca-control/downloads',
      ...defaults, ...env } })
  return result
}

test('auto 探测：有 /www/server/panel 或 bt 命令判为宝塔，否则普通；显式 --env 优先', () => {
  for (const [options, env, want] of [
    [{}, {}, 'bt|9.2.0|8888'],
    [{ panel: false }, {}, 'plain||'],
    [{ panel: false, btCommand: true }, {}, 'bt||'],
    [{}, { INSTALL_ENV: 'plain' }, 'plain|9.2.0|8888'],
    [{ panel: false }, { INSTALL_ENV: 'bt' }, 'bt||'],
  ]) {
    const root = fixture(options)
    try {
      const result = run(root, 'resolve_install_env; printf "%s|%s|%s" "$INSTALL_ENV" "$BT_VERSION" "$BT_PANEL_PORT"', env)
      assert.equal(result.status, 0, result.stderr)
      assert.equal(result.stdout, want, JSON.stringify(options) + JSON.stringify(env))
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
  const root = fixture()
  try {
    const bad = run(root, 'resolve_install_env', { INSTALL_ENV: 'docker' })
    assert.notEqual(bad.status, 0)
    assert.match(bad.stderr, /--env must be auto, bt or plain/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('宝塔模式：被占的依赖端口自动换成空闲替代端口，Web 改用回环替代端口；普通模式保持默认', () => {
  const root = fixture({ listen: [80, 443, 888, 3306, 5432, 6379, 8888, 15432] })
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; printf "%s %s %s %s %s %s %s %s" "$WEB_PORT" "$PG_PORT" "$REDIS_PORT" "$CH_HTTP_PORT" "$CH_TCP_PORT" "$CH_MYSQL_PORT" "$CH_POSTGRESQL_PORT" "$CH_INTERSERVER_PORT"')
    assert.equal(result.status, 0, result.stderr)
    // 5432 与首选替代 15432 都被占 -> 15433；6379 -> 16379；未占用的保持默认。
    assert.equal(result.stdout, '18443 15433 16379 8123 9000 9004 9005 9009')
  } finally { rmSync(root, { recursive: true, force: true }) }
  const plain = fixture({ panel: false, listen: [5432] })
  try {
    const result = run(plain, 'resolve_install_env; plan_install_ports; printf "%s %s %s" "$WEB_PORT" "$PG_PORT" "$REDIS_PORT"')
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, '443 5432 6379', '普通模式不换端口（占用仍由预检判不通过）')
  } finally { rmSync(plain, { recursive: true, force: true }) }
})

test('宝塔模式：--web-port 被占、与网关/保留端口冲突时报错', () => {
  for (const [port, listen, reason] of [
    ['18443', [18443], /--web-port 18443 is already in use/],
    ['21443', [], /--web-port 21443 conflicts/],
    ['8080', [], /--web-port 8080 conflicts/],
    ['80', [], /--web-port must be between 1024 and 65535/],
  ]) {
    const root = fixture({ listen })
    try {
      const result = run(root, 'resolve_install_env; plan_install_ports', { WEB_PORT: port })
      assert.notEqual(result.status, 0, port)
      assert.match(result.stderr, reason)
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

test('预检端口清单：宝塔模式不检查 443/80 与已换走的依赖端口，改查替代端口', () => {
  const root = fixture({ listen: [80, 443, 5432, 6379] })
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; control_preflight_ports')
    assert.equal(result.status, 0, result.stderr)
    const ports = result.stdout.trim().split('\n').map((entry) => entry.split(':')[0])
    for (const port of ['443', '80', '5432', '6379']) assert.ok(!ports.includes(port), `不应检查 ${port}`)
    for (const port of ['18443', '15432', '16379', '8123', '9000', '21443', '21444', '8080']) assert.ok(ports.includes(port), `应检查 ${port}`)
  } finally { rmSync(root, { recursive: true, force: true }) }
  const plain = fixture({ panel: false })
  try {
    const result = run(plain, 'resolve_install_env; plan_install_ports; control_preflight_ports')
    const ports = result.stdout.trim().split('\n').map((entry) => entry.split(':')[0])
    for (const port of ['443', '80', '5432', '6379']) assert.ok(ports.includes(port), `普通模式应检查 ${port}`)
  } finally { rmSync(plain, { recursive: true, force: true }) }
})

test('宝塔预检中文清单：版本、面板端口、替代端口、手工步骤与防火墙放行端口', () => {
  const root = fixture({ listen: [80, 443, 5432, 8888] })
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; bt_preflight_records; PREFLIGHT_ASSUME_YES=true; preflight_report "[t]"')
    assert.equal(result.status, 0, result.stderr)
    const text = result.stderr
    assert.match(text, /宝塔环境：检测到宝塔面板 9\.2\.0，面板端口 8888（不改动宝塔的 nginx、MySQL 与面板）/)
    assert.match(text, /端口调整：PostgreSQL 5432 已被占用，改用 15432/)
    assert.match(text, /管理端网页：本机 127\.0\.0\.1:18443/)
    assert.match(text, /宝塔手工步骤/)
    assert.match(text, /在宝塔「网站」添加站点 cdnca\.com/)
    assert.match(text, /反向代理到 https:\/\/127\.0\.0\.1:18443/)
    assert.match(text, /宝塔防火墙：.*443.*21443.*21444/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('宝塔模式要求域名：IP 管理端地址不通过', () => {
  const root = fixture()
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; bt_preflight_records; preflight_report "[t]"', { CONTROL_DOMAIN: '203.0.113.7' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /宝塔模式需要域名/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('反代配置：location ^~ / 转发到回环 HTTPS 并传递客户端地址与 WebSocket 头', () => {
  const root = fixture()
  try {
    const result = run(root, 'WEB_PORT=18443; bt_proxy_config')
    assert.equal(result.status, 0, result.stderr)
    const config = result.stdout
    assert.match(config, /location \^~ \/ \{/)
    assert.match(config, /proxy_pass https:\/\/127\.0\.0\.1:18443;/)
    assert.match(config, /proxy_set_header Host \$host;/)
    assert.match(config, /proxy_set_header X-Real-IP \$remote_addr;/)
    assert.match(config, /proxy_ssl_server_name on;/)
    assert.match(config, /proxy_ssl_name cdnca\.com;/)
    assert.match(config, /proxy_set_header Upgrade \$http_upgrade;/)
    assert.match(config, /client_max_body_size 0;/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

function btNginxFixture({ includeProxy = true, testOk = true, existing = false } = {}) {
  const root = fixture()
  mkdirSync(join(root, 'www/server/panel/vhost/nginx'), { recursive: true })
  mkdirSync(join(root, 'www/server/nginx/sbin'), { recursive: true })
  const site = join(root, 'www/server/panel/vhost/nginx/cdnca.com.conf')
  writeFileSync(site, `server {\n    listen 443 ssl;\n    server_name cdnca.com;\n${includeProxy ? '    include /www/server/panel/vhost/nginx/proxy/cdnca.com/*.conf;\n' : ''}}\n`)
  if (existing) {
    mkdirSync(join(root, 'www/server/panel/vhost/nginx/proxy/cdnca.com'), { recursive: true })
    writeFileSync(join(root, 'www/server/panel/vhost/nginx/proxy/cdnca.com/cdnca-control.conf'), 'old\n')
  }
  // 假 nginx：-t 按夹具返回，-s reload 记一笔。
  writeFileSync(join(root, 'www/server/nginx/sbin/nginx'),
    `#!/bin/sh\necho "$*" >> "${root}/nginx.calls"\ncase "$1" in -t) ${testOk ? 'exit 0' : 'echo "nginx: [emerg] bad" >&2; exit 1'} ;; esac\nexit 0\n`)
  chmodSync(join(root, 'www/server/nginx/sbin/nginx'), 0o755)
  return root
}

test('--bt-proxy：写入站点 proxy 目录、nginx -t 通过后 reload', () => {
  const root = btNginxFixture()
  try {
    const result = run(root, 'WEB_PORT=18443; bt_install_proxy')
    assert.equal(result.status, 0, result.stderr)
    const written = readFileSync(join(root, 'www/server/panel/vhost/nginx/proxy/cdnca.com/cdnca-control.conf'), 'utf8')
    assert.match(written, /proxy_pass https:\/\/127\.0\.0\.1:18443;/)
    assert.deepEqual(readFileSync(join(root, 'nginx.calls'), 'utf8').trim().split('\n'), ['-t', '-s reload'])
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('--bt-proxy：nginx -t 失败时恢复原文件且不 reload', () => {
  const root = btNginxFixture({ testOk: false, existing: true })
  try {
    const result = run(root, 'WEB_PORT=18443; bt_install_proxy')
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /宝塔 nginx 配置检查未通过，已恢复/)
    assert.equal(readFileSync(join(root, 'www/server/panel/vhost/nginx/proxy/cdnca.com/cdnca-control.conf'), 'utf8'), 'old\n')
    assert.deepEqual(readFileSync(join(root, 'nginx.calls'), 'utf8').trim().split('\n'), ['-t'])
  } finally { rmSync(root, { recursive: true, force: true }) }
  const fresh = btNginxFixture({ testOk: false })
  try {
    const result = run(fresh, 'WEB_PORT=18443; bt_install_proxy')
    assert.notEqual(result.status, 0)
    assert.ok(!existsSync(join(fresh, 'www/server/panel/vhost/nginx/proxy/cdnca.com/cdnca-control.conf')), '新写的文件应删除')
  } finally { rmSync(fresh, { recursive: true, force: true }) }
})

test('--bt-proxy：站点不存在或站点配置没有 proxy include 时不改任何文件并提示手工步骤', () => {
  const root = btNginxFixture({ includeProxy: false })
  try {
    const result = run(root, 'WEB_PORT=18443; bt_install_proxy')
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /站点配置没有引用 proxy 目录/)
    assert.ok(!existsSync(join(root, 'www/server/panel/vhost/nginx/proxy/cdnca.com')))
  } finally { rmSync(root, { recursive: true, force: true }) }
  const missing = fixture()
  try {
    const result = run(missing, 'WEB_PORT=18443; bt_install_proxy')
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /宝塔里没有站点 cdnca\.com/)
  } finally { rmSync(missing, { recursive: true, force: true }) }
})

test('安装器把宝塔模式接到 Web 监听、证书、自检与升级下载信任', () => {
  const nginx = block('write_nginx_config')
  assert.match(nginx, /listen \$\{WEB_LISTEN\} ssl http2;/)
  assert.match(nginx, /\$\{WEB_REAL_IP\}/)
  assert.match(block('issue_public_certificate'), /INSTALL_ENV" = bt/)
  for (const name of ['setup_web', 'verify_native_plan_source']) {
    assert.match(block(name), /--resolve "\$\{CONTROL_DOMAIN\}:\$\{WEB_PORT\}:127\.0\.0\.1"/, name)
    assert.match(block(name), /\$\(local_web_origin\)/, name)
  }
  // fix-btenv4：信任文档由 control-api 按 control.env（制品地址端口 + CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE）生成。
  assert.match(block('publish_upgrade_trust'), /"\$CONTROL_BINARY" native-backup publish-node-install-trust/)
  assert.match(block('write_environment'), /\n\$\(upgrade_download_root_env\)\n/)
  assert.match(block('upgrade_download_root_ca_file'), /INSTALL_ENV:-\}" = bt/)
  assert.match(block('configure_selinux'), /selinux_http_port "\$WEB_PORT"/)
  assert.match(block('parse_args'), /--env\)/)
  assert.match(block('parse_args'), /--web-port\)/)
  assert.match(block('parse_args'), /--bt-proxy\)/)
  assert.match(block('main'), /bt_report/)
})

test('端口档案：宝塔模式写入实际端口（0644，依赖安装前），普通模式不写', () => {
  const root = fixture({ listen: [5432, 6379] })
  try {
    const profile = join(root, 'deps/runtime.env')
    const body = `DEPENDENCY_PORTS_FILE=${JSON.stringify(profile)}; resolve_install_env; plan_install_ports; write_dependency_ports`
    const script = ['set -Eeuo pipefail', `source ${JSON.stringify(library)}`, block('log'), block('warn'), block('fail'), block('valid_port'),
      reserved, ...btFunctions.map(block), block('write_dependency_ports'), body].join('\n')
    const env = { PATH: '/usr/bin:/bin', PREFLIGHT_ROOT: root, BT_ROOT: root, INSTALL_ENV: 'auto', WEB_PORT: '', MASTER_PORT: '443',
      GATEWAY_ENROLLMENT_PORT: '21443', GATEWAY_AGENT_PORT: '21444', SKIP_DEPENDENCIES: 'false', BT_PROXY: 'false', ...defaults }
    let result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(readFileSync(profile, 'utf8'),
      'ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\nPG_PORT=15432\nREDIS_PORT=16379\nCH_HTTP_PORT=8123\nCH_TCP_PORT=9000\nCH_MYSQL_PORT=9004\nCH_POSTGRESQL_PORT=9005\nCH_INTERSERVER_PORT=9009\n')
    rmSync(profile)
    result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { ...env, INSTALL_ENV: 'plain' } })
    assert.equal(result.status, 0, result.stderr)
    assert.ok(!existsSync(profile))
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('实际端口接到 DATABASE_URL、REDIS_URL、PostgreSQL/Redis 就绪检查与网关 Redis', () => {
  const normalise = block('normalise_defaults')
  assert.match(normalise, /@127\.0\.0\.1:\$PG_PORT\/cdnca\?sslmode=disable/)
  assert.match(normalise, /REDIS_URL=\$\{REDIS_URL:-redis:\/\/127\.0\.0\.1:\$REDIS_PORT\/0\}/)
  assert.doesNotMatch(block('prepare_database'), /-p 5432/)
  assert.match(block('prepare_database'), /-p "\$PG_PORT"/)
  assert.match(block('generate_gateway_access_secrets'), /@127\.0\.0\.1:\$\{REDIS_PORT\}\/0/)
  assert.match(block('configure_redis_gateway_access'), /-p "\$REDIS_PORT"/)
  assert.ok(block('main').indexOf('write_dependency_ports') < block('main').indexOf('configure_runtime_dependencies'))
  assert.match(source, /^REDIS_URL=""$/m)
})

test('宝塔环境管理端网页用宝塔 nginx 二进制与 mime.types，普通环境不变', () => {
  const root = fixture()
  try {
    mkdirSync(join(root, 'www/server/nginx/sbin'), { recursive: true })
    writeFileSync(join(root, 'www/server/nginx/sbin/nginx'), '#!/bin/sh\n', { mode: 0o755 })
    const body = 'printf "%s|%s" "$(control_nginx_bin)" "$(control_nginx_mime_types)"'
    const script = ['set -Eeuo pipefail', block('control_nginx_bin'), block('control_nginx_mime_types'), body].join('\n')
    let result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', BT_ROOT: root, INSTALL_ENV: 'bt' } })
    assert.equal(result.stdout, `${root}/www/server/nginx/sbin/nginx|${root}/www/server/nginx/conf/mime.types`)
    result = spawnSync('bash', ['-c', `nginx() { :; }; ${script}`], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', BT_ROOT: root, INSTALL_ENV: 'plain' } })
    assert.match(result.stdout, /\|\/etc\/nginx\/mime\.types$/)
    for (const name of ['write_nginx_config', 'setup_web']) assert.match(block(name), /nginx_bin=\$\(control_nginx_bin\)/, name)
    assert.match(block('write_nginx_config'), /include \$\(control_nginx_mime_types\);/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

// fix-btenv2 ①：宝塔模式节点升级下载走我方 nginx 直连端口（主控自带 CA），不经宝塔站点证书。
test('宝塔模式：节点升级下载直连端口默认 19445，被占顺延并列入预检端口与防火墙；普通模式没有', () => {
  const root = fixture({ listen: [80, 443, 19445] })
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; printf "%s\\n" "$NODE_DOWNLOAD_PORT"; control_preflight_ports')
    assert.equal(result.status, 0, result.stderr)
    const [port, ...entries] = result.stdout.trim().split('\n')
    assert.equal(port, '19446')
    assert.ok(entries.includes('19446:节点升级下载'), entries.join(','))
  } finally { rmSync(root, { recursive: true, force: true }) }
  const plain = fixture({ panel: false })
  try {
    const result = run(plain, 'resolve_install_env; plan_install_ports; printf "[%s]" "$NODE_DOWNLOAD_PORT"')
    assert.equal(result.stdout, '[]')
  } finally { rmSync(plain, { recursive: true, force: true }) }
})

// fix-btenv3 ①：网关端口（节点默认 19443/19444、--gateway-ports 自选或随机值）与直连下载端口不撞。
test('宝塔模式：直连下载端口避开网关实际端口与已占端口并顺延，端口调整写明原因', () => {
  for (const [gateway, listen, expected] of [
    [['19443', '19444'], [80, 443], '19445'],
    [['19445', '19446'], [80, 443], '19447'],
    [['19443', '19444'], [80, 443, 19445, 19446], '19447'],
    [['19445', '21444'], [19446], '19447'],
  ]) {
    const root = fixture({ listen })
    try {
      const result = run(root, 'resolve_install_env; plan_install_ports; printf "%s\\n" "$NODE_DOWNLOAD_PORT"; printf "%s\\n" ${BT_PORT_CHANGES[@]+"${BT_PORT_CHANGES[@]}"}',
        { GATEWAY_ENROLLMENT_PORT: gateway[0], GATEWAY_AGENT_PORT: gateway[1] })
      assert.equal(result.status, 0, result.stderr)
      const [port, ...changes] = result.stdout.trim().split('\n')
      assert.equal(port, expected, `网关 ${gateway} 占用 ${listen}`)
      assert.ok(!gateway.includes(port), '不得与网关端口相同')
      if (expected !== '19445') assert.ok(changes.includes(`节点升级下载 19445 已被占用或与网关端口冲突，改用 ${expected}`), changes.join('|'))
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

test('宝塔预检列出全部实际端口（含顺延）与节点升级下载直连端口、防火墙放行直连端口', () => {
  const root = fixture({ listen: [80, 443, 5432, 15432, 18443, 8888] })
  try {
    const result = run(root, 'resolve_install_env; plan_install_ports; bt_preflight_records; PREFLIGHT_ASSUME_YES=true; preflight_report "[t]"')
    assert.equal(result.status, 0, result.stderr)
    const text = result.stderr
    assert.match(text, /端口调整：管理端网页 18443 已被占用，改用 18444/)
    assert.match(text, /端口调整：PostgreSQL 5432 已被占用，改用 15433/)
    assert.match(text, /端口规划：管理端网页 127\.0\.0\.1:18444、节点升级下载 19445、PostgreSQL 15433、Redis 6379、ClickHouse-HTTP 8123、ClickHouse 9000/)
    assert.match(text, /节点升级下载：直连端口 19445/)
    assert.match(text, /宝塔防火墙：.*443.*21443.*21444.*19445/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

// 证书夹具：自建 CA（作系统信任库）签发站点证书；另有自签证书。
// 目标机是 OpenSSL 1.1+/3（-verify_hostname）；macOS /usr/bin/openssl 是 LibreSSL，有 OpenSSL 3 时放进夹具 PATH。
const openssl = ['/opt/homebrew/bin/openssl', '/usr/local/bin/openssl', '/usr/bin/openssl']
  .find((path) => existsSync(path) && /^OpenSSL [3-9]/.test(spawnSync(path, ['version'], { encoding: 'utf8' }).stdout))
function certFixture(root, { trusted = true, host = 'cdnca.com' } = {}) {
  const dir = join(root, 'www/server/panel/vhost/cert/cdnca.com')
  mkdirSync(dir, { recursive: true })
  if (openssl !== '/usr/bin/openssl') symlinkSync(openssl, join(root, 'bin/openssl'))
  const sh = (args) => { const r = spawnSync(openssl, args, { encoding: 'utf8', cwd: root }); assert.equal(r.status, 0, r.stderr) }
  sh(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Test Root', '-keyout', 'ca.key', '-out', 'ca.pem',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
  writeFileSync(join(root, 'bundle.pem'), readFileSync(join(root, 'ca.pem')))
  if (trusted) {
    sh(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=${host}`, '-keyout', 'leaf.key', '-out', 'leaf.csr'])
    writeFileSync(join(root, 'ext.cnf'), `subjectAltName=DNS:${host}\nextendedKeyUsage=serverAuth\n`)
    sh(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '10', '-extfile', 'ext.cnf', '-out', 'leaf.pem'])
    writeFileSync(join(dir, 'fullchain.pem'), readFileSync(join(root, 'leaf.pem')))
  } else {
    sh(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', `/CN=${host}`, '-addext', `subjectAltName=DNS:${host}`,
      '-keyout', 'self.key', '-out', join(dir, 'fullchain.pem')])
  }
}

test('宝塔站点证书预检：受信通过；自签/域名不符/未申请给出中文提示（节点升级下载不受影响）', { skip: !openssl && '需要 OpenSSL 1.1+' }, () => {
  const untrusted = /\[[^\]]+\] 宝塔站点证书：站点 cdnca\.com 的证书不受系统信任（自签、证书链不完整、已过期或域名不符）/
  for (const [name, setup, pattern] of [
    ['trusted', (root) => certFixture(root), /\[通过\] 宝塔站点证书：站点 cdnca\.com 的证书受系统信任/],
    ['self-signed', (root) => certFixture(root, { trusted: false }), untrusted],
    ['wrong-host', (root) => certFixture(root, { host: 'other.test' }), untrusted],
    ['missing', (root) => writeFileSync(join(root, 'bundle.pem'), ''), /宝塔站点证书：站点 cdnca\.com 还没有证书/],
  ]) {
    const root = fixture()
    try {
      setup(root)
      const result = run(root, 'resolve_install_env; plan_install_ports; bt_preflight_records; PREFLIGHT_ASSUME_YES=true; preflight_report "[t]"',
        { BT_CA_BUNDLE: join(root, 'bundle.pem') })
      assert.equal(result.status, 0, result.stderr)
      assert.match(result.stderr, pattern, name)
      if (name !== 'trusted') {
        assert.match(result.stderr, /建议：.*Let's Encrypt.*节点升级下载走直连端口 19445（主控自带 CA），不受站点证书影响/, name)
      }
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

test('宝塔模式接线：直连下载 server、升级信任嵌主控根 CA 与直连端口、制品地址、SELinux', () => {
  const nginx = block('write_nginx_config')
  assert.match(nginx, /\$\(node_download_server\)/)
  const server = block('node_download_server')
  assert.match(server, /listen \$\{NODE_DOWNLOAD_PORT\} ssl;/)
  assert.match(server, /location \^~ \/downloads\/edge-agent\/upgrades\/sha256\//)
  assert.match(server, /ssl_certificate \$\{PKI_DIR\}\/public-server\.pem;/)
  assert.match(server, /location \/ \{ return 404; \}/)
  // 信任文档的下载端口取自制品地址（control-api 生成，fix-btenv4）。
  assert.match(block('upgrade_download_root_ca_file'), /INSTALL_ENV:-\}" = bt[\s\S]*root-ca-cert\.pem/)
  assert.match(block('write_environment'), /CONTROL_UPGRADE_ARTIFACT_BASE_URL=\$\(upgrade_download_origin\)\/downloads\/edge-agent\/upgrades\/sha256/)
  assert.match(block('configure_selinux'), /selinux_http_port "\$NODE_DOWNLOAD_PORT"/)
  const root = fixture()
  try {
    const script = ['set -Eeuo pipefail', block('upgrade_download_origin'), block('node_download_server'),
      'printf "%s\\n" "$(upgrade_download_origin)"; node_download_server'].join('\n')
    const env = { PATH: '/usr/bin:/bin', CONTROL_DOMAIN: 'cdnca.com', CONTROL_ORIGIN: 'https://cdnca.com', MASTER_PORT: '443',
      PKI_DIR: '/k', DOWNLOAD_DIR: '/d' }
    let result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { ...env, INSTALL_ENV: 'bt', NODE_DOWNLOAD_PORT: '19445' } })
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /^https:\/\/cdnca\.com:19445\n/)
    assert.match(result.stdout, /listen 19445 ssl;/)
    assert.match(result.stdout, /alias \/d\/edge-agent\/upgrades\/sha256\/;/)
    result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { ...env, INSTALL_ENV: 'plain', NODE_DOWNLOAD_PORT: '' } })
    assert.equal(result.stdout, 'https://cdnca.com\n', '普通模式不加直连 server')
  } finally { rmSync(root, { recursive: true, force: true }) }
})

// fix-btenv3 ②：升级信任文档与 control.env 的下载根 CA 同一规则；control.env 写 CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE
// 供主控把当前下载策略签进升级执行（迁移后节点跟随，无需重装）。
test('下载根 CA：宝塔/内置证书用私有根，系统验不过的运营者证书用其自身，公网证书不写（节点用系统根）', () => {
  const functions = [block('upgrade_download_root_ca_file'), block('upgrade_download_root_env')].join('\n')
  const cases = [
    [{ INSTALL_ENV: 'bt', PUBLIC_CERT_FILE: '/bt/site.pem', TRUST: '' }, 'CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/k/root-ca-cert.pem'],
    [{ INSTALL_ENV: 'plain', PUBLIC_CERT_FILE: '', TRUST: '' }, 'CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/k/root-ca-cert.pem'],
    [{ INSTALL_ENV: 'plain', PUBLIC_CERT_FILE: '/op.pem', TRUST: '--cacert' }, 'CONTROL_UPGRADE_DOWNLOAD_ROOT_CA_FILE=/k/public-cert.pem'],
    [{ INSTALL_ENV: 'plain', PUBLIC_CERT_FILE: '/op.pem', TRUST: '' }, ''],
  ]
  for (const [env, expected] of cases) {
    const script = ['set -Eeuo pipefail', 'public_https_trust_args() { [ -z "$TRUST" ] || printf "%s\\n/x\\n" "$TRUST"; }', functions,
      'printf "[%s]" "$(upgrade_download_root_env)"'].join('\n')
    const result = spawnSync('bash', ['-c', script], { encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin', PKI_DIR: '/k', PUBLIC_CERT_PATH: '/k/public-cert.pem', ...env } })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, `[${expected}]`, JSON.stringify(env))
  }
  assert.match(block('write_environment'), /CONTROL_UPGRADE_ARTIFACT_BASE_URL=.*\n\$\(upgrade_download_root_env\)\n/)
  // 信任文档与签进升级执行的下载策略都从 control.env 这一行取根 CA（fix-btenv4）。
  assert.match(block('publish_upgrade_trust'), /native-backup publish-node-install-trust/)
})

// fix-btenv3 ②：迁移恢复时 control-api 增删的直连下载 server 与安装器同文（Go 测试读同一金标文件）。
test('node_download_server 与 nativebackup 金标 testdata/node-download-server.conf 一致', () => {
  const script = ['set -Eeuo pipefail', block('node_download_server'), 'node_download_server'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', INSTALL_ENV: 'bt',
    NODE_DOWNLOAD_PORT: '19445', PKI_DIR: '/etc/cdnca-control/keys/pki', DOWNLOAD_DIR: '/var/lib/cdnca-control/downloads' } })
  assert.equal(result.status, 0, result.stderr)
  const golden = readFileSync(new URL('../services/control-api/internal/nativebackup/testdata/node-download-server.conf', import.meta.url), 'utf8')
  assert.equal(result.stdout, golden)
  assert.match(source, /^readonly PKI_DIR="\$\{KEY_DIR\}\/pki"$/m)
  assert.match(source, /^readonly KEY_DIR="\$\{CONFIG_DIR\}\/keys"$/m)
  assert.match(source, /^readonly DOWNLOAD_DIR="\$\{DATA_DIR\}\/downloads"$/m)
})

// fix-btenv2 ④：宝塔 Apache / OpenLiteSpeed 只给可复制片段，不自动写入。
test('Apache 片段：校验回环证书、保留 Host、覆盖 X-Real-IP、WebSocket、排除证书验证路径', () => {
  const result = run(fixture(), 'WEB_PORT=18443; DOWNLOAD_DIR=/var/lib/cdnca-control/downloads; bt_proxy_apache_config')
  assert.equal(result.status, 0, result.stderr)
  const config = result.stdout
  assert.match(config, /SSLProxyEngine On/)
  assert.match(config, /SSLProxyCACertificateFile \/var\/lib\/cdnca-control\/downloads\/gateway-ca\.pem/)
  assert.match(config, /SSLProxyVerify require/)
  assert.match(config, /ProxyPreserveHost On/)
  assert.match(config, /RequestHeader set X-Real-IP "expr=%\{REMOTE_ADDR\}"/)
  assert.match(config, /RequestHeader set X-Forwarded-Proto "https"/)
  assert.match(config, /ProxyPass \/\.well-known\/ !/)
  assert.match(config, /ProxyPass \/ https:\/\/127\.0\.0\.1:18443\/ upgrade=websocket/)
  assert.match(config, /ProxyPassReverse \/ https:\/\/127\.0\.0\.1:18443\//)
  assert.ok(config.indexOf('ProxyPass /.well-known/ !') < config.indexOf('ProxyPass / https'), '排除项必须在前')
})

test('OpenLiteSpeed 片段：proxy 外部应用指向回环 HTTPS，context / 交给它', () => {
  const result = run(fixture(), 'WEB_PORT=18443; bt_proxy_openlitespeed_config')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /extprocessor cdnca-control \{\n\s+type\s+proxy\n\s+address\s+https:\/\/127\.0\.0\.1:18443\n/)
  assert.match(result.stdout, /context \/ \{\n\s+type\s+proxy\n\s+handler\s+cdnca-control\n/)
})

test('宝塔 Apache / OpenLiteSpeed：预检警告附可复制片段，安装结束保存片段并打印，不自动写入', () => {
  for (const [server, path, needle, file] of [
    ['Apache', 'www/server/apache/bin/httpd', /ProxyPass \/ https:\/\/127\.0\.0\.1:18443\//, 'bt-proxy-apache.conf'],
    ['OpenLiteSpeed', 'usr/local/lsws/bin/lswsctrl', /address\s+https:\/\/127\.0\.0\.1:18443/, 'bt-proxy-openlitespeed.conf'],
  ]) {
    const root = fixture()
    try {
      mkdirSync(join(root, path, '..'), { recursive: true })
      writeFileSync(join(root, path), '#!/bin/sh\n', { mode: 0o755 })
      const result = run(root, 'resolve_install_env; plan_install_ports; bt_preflight_records; PREFLIGHT_ASSUME_YES=true; preflight_report "[t]"; bt_report')
      assert.equal(result.status, 0, result.stderr)
      const text = result.stderr
      assert.match(text, new RegExp(`\\[警告\\] 宝塔${server}：宝塔使用 ${server}，安装器不会自动写入反向代理`), server)
      const preflight = text.slice(0, text.indexOf('检测结果'))
      assert.match(preflight, needle, `${server} 预检应附片段`)
      assert.match(readFileSync(join(root, file), 'utf8'), needle)
      assert.match(text, new RegExp(`已保存到 ${root}/${file.replace('.', '\\.')}`))
      assert.ok(!existsSync(join(root, 'www/server/panel/vhost/nginx/proxy')), '不写宝塔站点配置')
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})

// fix-btenv2 ③：迁移到宝塔目标时 control-api 生成的 bt-proxy.conf 与安装器同文（Go 测试读同一金标文件）。
test('bt_proxy_config 与 nativebackup 金标 testdata/bt-proxy.conf 一致；migrate-from 结尾提示宝塔反代', () => {
  const result = run(fixture(), 'WEB_PORT=18443; bt_proxy_config')
  assert.equal(result.status, 0, result.stderr)
  const golden = readFileSync(new URL('../services/control-api/internal/nativebackup/testdata/bt-proxy.conf', import.meta.url), 'utf8')
  assert.equal(result.stdout, golden)
  assert.match(block('migrate_main'), /INSTALL_ENV" = bt[\s\S]*bt-proxy\.conf/)
})

test('migrate-from：接受 --env，预检按目标环境，依赖安装前写端口档案', () => {
  assert.match(block('migrate_parse_args'), /--env\) need_value "\$@"; INSTALL_ENV=\$2/)
  const main = block('migrate_main')
  assert.ok(main.indexOf('run_preflight') < main.indexOf('write_dependency_ports'))
  assert.ok(main.indexOf('write_dependency_ports') < main.indexOf('install-ubuntu-dependencies.sh" install'))
  assert.match(block('migrate_usage'), /--env auto\|bt\|plain/)
})
