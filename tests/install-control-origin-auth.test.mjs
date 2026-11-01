// install-control.sh CDN 回源鉴权（c3 F4，与 install-auth.sh origin-auth / management-web client_ip.go 同语义）：
//   - --origin-auth 安装与 origin-auth 子命令都把密钥写进 root 0600 的 origin-auth.conf（nginx map），nginx.conf 只 include；
//   - 每个反代 location 的 X-Real-IP/X-Forwarded-For 改用 $cdnca_client_ip，并丢弃 X-Cdnca-Origin-Key；
//   - 暗号匹配且 real-ip 头是单个合法 IP（X-Forwarded-For 取最右一跳）才用它，否则用 TCP 对端；
//   - 子命令幂等；nginx -t 或重载失败时恢复原配置。
// 真实 nginx 用例需 CDNCA_TEST_NGINX_BIN（同 install-control-nginx-request-line.test.mjs）。
import assert from 'node:assert/strict'
import { spawn, spawnSync } from './helpers/large-bash-script.mjs'
import { chmodSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { request } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].trimEnd().endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}
const helpers = ['log', 'fail', 'need_value', 'origin_auth_valid_header', 'origin_auth_check_header', 'origin_auth_secret',
  'origin_auth_write_conf', 'origin_auth_apply_nginx', 'origin_auth_usage', 'origin_auth_main',
  'control_nginx_bin', 'control_nginx_mime_types', 'node_download_server'].map(block).join('\n') + '\n' +
  // heredoc 里有顶格的 }，与 install-control-nginx-request-line.test.mjs 同样按下一个函数定界。
  source.match(/^write_nginx_config\(\) \{[\s\S]*?^\}\n\n(?=# 验证节点升级下载端点)/m)[0]
const secret = 'Ab0_-'.repeat(8) + 'cdnca-origin-test-key'
const nginxBinary = process.env.CDNCA_TEST_NGINX_BIN

function shell(root, script, env = {}) {
  return spawnSync('bash', ['-c', ['set -Eeuo pipefail', helpers, script].join('\n')], { encoding: 'utf8', timeout: 10000, env: {
    ...process.env, CONFIG_DIR: root, NGINX_CONF: join(root, 'nginx.conf'), NGINX_RUNTIME_DIR: join(root, 'runtime'),
    ORIGIN_AUTH_CONF: join(root, 'origin-auth.conf'), ORIGIN_AUTH_SECRET_FILE: join(root, 'origin-auth.secret'),
    MASTER_PORT: '8443', WEB_LISTEN: '8443', WEB_REAL_IP: '', INSTALL_ENV: 'plain', BT_ROOT: '', WEB_ROOT: root, DATA_DIR: root,
    NATIVE_ROOT: root, DOWNLOAD_DIR: join(root, 'downloads'), PUBLIC_CERT_PATH: join(root, 'server.crt'),
    PUBLIC_KEY_PATH: join(root, 'server.key'), ORIGIN_AUTH: 'false', REAL_IP_HEADER: 'X-Forwarded-For', WEB_SERVICE_NAME: 'cdnca-control-web', TEMP_DIR: root, EUID: '0', ...env,
  } })
}
// nginx -t 由桩函数代替（语法由真实 nginx 用例验证）。
const stubNginx = 'nginx() { [ "$1" = -t ] && [ ! -e "$CONFIG_DIR/nginx-t-fails" ]; }; mkdir() { command mkdir "$@"; }'
function withRoot(run) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-origin-auth-')))
  try { return run(root) } finally { rmSync(root, { recursive: true, force: true }) }
}
function renderInstall(root, env = {}) {
  writeFileSync(join(root, 'origin-auth.secret'), `${secret}\n`, { mode: 0o600 })
  const result = shell(root, `${stubNginx}\nORIGIN_AUTH=true\nREAL_IP_HEADER=\${HEADER:-X-Forwarded-For}\nwrite_nginx_config`, env)
  assert.equal(result.status, 0, result.stderr)
  return { nginx: readFileSync(join(root, 'nginx.conf'), 'utf8'), auth: readFileSync(join(root, 'origin-auth.conf'), 'utf8') }
}
// 只认 location 自身（12 格缩进）的 proxy_pass：/v1/ 里嵌套的 gzip location（api-gzip）有自己的 proxy_pass，
// 请求头由外层继承，不能在那里截断外层 location。
function proxyBodies(config) {
  return [...config.matchAll(/location [^{]*\{((?:(?!\n        \})[\s\S])*?\n {12}proxy_pass http:\/\/127\.0\.0\.1:8080;)/g)]
    .map((match) => match[1]).filter((body) => body.includes('proxy_set_header'))
}

// 按 nginx map 语义计算 $cdnca_client_ip：键为 "~正则" 时按 PCRE 匹配（这里的正则 JS 与 PCRE 语义相同），命名捕获可作值。
function clientIP(authConf, headers, remote = '198.51.100.7') {
  const maps = [...authConf.matchAll(/^map (\S+) \$(\w+) \{\n([\s\S]*?)\n\}/gm)].map(([, input, output, body]) => ({
    input, output, entries: body.split('\n').map((line) => line.trim().match(/^(default|"[^"]*") (.+);$/)).map(([, key, value]) => ({ key, value })),
  }))
  assert.equal(maps.length, 3)
  const vars = { remote_addr: remote }
  for (const [name, value] of Object.entries(headers)) vars[`http_${name.toLowerCase().replaceAll('-', '_')}`] = value
  const expand = (text) => text.replace(/^"|"$/g, '').replace(/\$(\w+)/g, (_, name) => vars[name] ?? '')
  for (const map of maps) {
    const input = expand(map.input)
    let result = expand(map.entries.find((entry) => entry.key === 'default').value)
    for (const { key, value } of map.entries.filter((entry) => entry.key !== 'default')) {
      const pattern = key.slice(1, -1)
      assert.ok(pattern.startsWith('~'), `regex key: ${key}`)
      const match = new RegExp(pattern.slice(1)).exec(input)
      if (match) { Object.assign(vars, match.groups); result = expand(value); break }
    }
    vars[map.output] = result
  }
  return vars.cdnca_client_ip
}

test('--origin-auth: every proxy location forwards $cdnca_client_ip and drops the origin key', () => withRoot((root) => {
  const { nginx, auth } = renderInstall(root)
  assert.equal(nginx.split(`    include ${root}/origin-auth.conf;`).length, 2, 'include origin-auth.conf exactly once')
  assert.match(nginx, /include \/etc\/cdnca-upgrade\/plan-source-nginx\.conf;\n    include .*origin-auth\.conf;/)
  const proxies = proxyBodies(nginx)
  assert.equal(proxies.length, 5)
  for (const body of proxies) {
    assert.match(body, /proxy_set_header X-Real-IP \$cdnca_client_ip;/)
    assert.match(body, /proxy_set_header X-Forwarded-For \$cdnca_client_ip;\n\s+proxy_set_header X-Cdnca-Origin-Key "";/)
  }
  assert.doesNotMatch(nginx, /X-(?:Real-IP|Forwarded-For) \$remote_addr/)
  assert.ok(!nginx.includes(secret), 'nginx.conf never holds the secret')
  assert.ok(auth.includes(`"~^${secret}$" 1;`))
  assert.match(auth, /^proxy_set_header X-Cdnca-Origin-Key "";$/m)
  assert.equal(statSync(join(root, 'origin-auth.conf')).mode & 0o777, 0o600)
}))

test('without --origin-auth the nginx configuration keeps the TCP peer and has no origin-auth include', () => withRoot((root) => {
  const result = shell(root, `${stubNginx}\nORIGIN_AUTH=false\nwrite_nginx_config`)
  assert.equal(result.status, 0, result.stderr)
  const nginx = readFileSync(join(root, 'nginx.conf'), 'utf8')
  assert.doesNotMatch(nginx, /origin-auth\.conf;|cdnca_client_ip|X-Cdnca-Origin-Key/)
  assert.ok(!existsSync(join(root, 'origin-auth.conf')))
}))

test('X-Forwarded-For: matching key takes the right-most hop, anything else the TCP peer', () => withRoot((root) => {
  const { auth } = renderInstall(root)
  const key = { 'X-Cdnca-Origin-Key': secret }
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '203.0.113.9' }), '203.0.113.9')
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '10.0.0.1, 192.0.2.1 , 203.0.113.9' }), '203.0.113.9')
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '203.0.113.9, 2001:db8::7' }), '2001:db8::7')
  // 客户端伪造的地址只能在左边；最右一跳不是合法 IP 时不信头。
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '203.0.113.9, evil' }), '198.51.100.7')
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '256.1.1.1' }), '198.51.100.7')
  assert.equal(clientIP(auth, { ...key }), '198.51.100.7')
  // 暗号不对：错值、大小写不同、前后多字符、两个头被 nginx 合并、缺失。
  for (const wrong of ['nope', secret.toUpperCase(), `${secret}x`, `x${secret}`, `${secret}, ${secret}`, '']) {
    assert.equal(clientIP(auth, { 'X-Cdnca-Origin-Key': wrong, 'X-Forwarded-For': '203.0.113.9' }), '198.51.100.7', wrong)
  }
}))

test('single-value headers (CF-Connecting-IP) must hold exactly one address', () => withRoot((root) => {
  const { auth } = renderInstall(root, { HEADER: 'CF-Connecting-IP' })
  assert.match(auth, /^# real-ip-header: CF-Connecting-IP$/m)
  assert.match(auth, /^map \$http_cf_connecting_ip \$cdnca_origin_peer/m)
  const key = { 'X-Cdnca-Origin-Key': secret }
  assert.equal(clientIP(auth, { ...key, 'CF-Connecting-IP': ' 203.0.113.9 ' }), '203.0.113.9')
  assert.equal(clientIP(auth, { ...key, 'CF-Connecting-IP': '203.0.113.9, 192.0.2.1' }), '198.51.100.7')
  assert.equal(clientIP(auth, { ...key, 'X-Forwarded-For': '203.0.113.9' }), '198.51.100.7')
  assert.equal(clientIP(auth, { 'CF-Connecting-IP': '203.0.113.9' }), '198.51.100.7')
}))

test('header and secret validation', () => withRoot((root) => {
  let result = shell(root, 'REAL_IP_HEADER=X-Client-IP; origin_auth_check_header false')
  assert.notEqual(result.status, 0); assert.match(result.stderr, /--real-ip-header 只支持/)
  for (const header of ['X-Forwarded-For', 'X-Real-IP']) {
    result = shell(root, `REAL_IP_HEADER=${header}; origin_auth_check_header true`)
    assert.notEqual(result.status, 0, header); assert.match(result.stderr, /宝塔环境/)
  }
  assert.equal(shell(root, 'REAL_IP_HEADER=True-Client-IP; origin_auth_check_header true').status, 0)
  writeFileSync(join(root, 'origin-auth.secret'), 'short\n', { mode: 0o600 })
  result = shell(root, 'origin_auth_secret >/dev/null')
  assert.notEqual(result.status, 0); assert.match(result.stderr, /32–256/)
  writeFileSync(join(root, 'origin-auth.secret'), `${'a'.repeat(40)}"; } evil {\n`, { mode: 0o600 })
  assert.notEqual(shell(root, 'origin_auth_secret >/dev/null').status, 0, 'characters that would break the nginx map are refused')
  rmSync(join(root, 'origin-auth.secret'))
  result = shell(root, 'origin_auth_secret')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /^[0-9a-f]{64}$/)
  assert.equal(readFileSync(join(root, 'origin-auth.secret'), 'utf8').trim(), result.stdout)
  assert.equal(statSync(join(root, 'origin-auth.secret')).mode & 0o777, 0o600)
}))

// origin-auth 子命令：在已装主控的 nginx.conf 上改写；systemctl/nginx 是桩，unit 指向桩 nginx。
function installed(root) {
  assert.equal(shell(root, `${stubNginx}\nORIGIN_AUTH=false\nwrite_nginx_config`).status, 0)
  const bin = join(root, 'nginx-bin')
  writeFileSync(bin, '#!/bin/sh\n[ "$1" = -t ] && [ ! -e "$(dirname "$0")/nginx-t-fails" ]\n'); chmodSync(bin, 0o755)
  writeFileSync(join(root, 'web.service'), `[Service]\nExecStart=${bin} -c x -p y -g 'daemon off;'\n`)
  return readFileSync(join(root, 'nginx.conf'), 'utf8')
}
function subcommand(root, args = '') {
  const script = [`systemctl() { printf '%s\\n' "$*" >>"$CONFIG_DIR/systemctl.log"; [ ! -e "$CONFIG_DIR/reload-fails" ]; }`,
    // 子命令从 /etc/systemd/system/<web>.service 读 nginx 路径；测试改指临时文件。
    block('origin_auth_main').replace('"/etc/systemd/system/${WEB_SERVICE_NAME}.service"', '"$CONFIG_DIR/web.service"'),
    `origin_auth_main ${args}`].join('\n')
  return shell(root, script)
}

test('origin-auth subcommand enables, is idempotent and can switch header', () => withRoot((root) => {
  installed(root)
  writeFileSync(join(root, 'shared.secret'), `${secret}\n`, { mode: 0o600 })
  let result = subcommand(root, `--secret-file ${join(root, 'shared.secret')} --real-ip-header CF-Connecting-IP`)
  assert.equal(result.status, 0, result.stderr)
  assert.ok(!result.stdout.includes(secret) && !result.stderr.includes(secret), 'secret never printed')
  const once = readFileSync(join(root, 'nginx.conf'), 'utf8')
  assert.equal(proxyBodies(once).filter((body) => body.includes('$cdnca_client_ip')).length, 5)
  assert.match(readFileSync(join(root, 'origin-auth.conf'), 'utf8'), /\$http_cf_connecting_ip/)
  assert.equal(readFileSync(join(root, 'systemctl.log'), 'utf8'), 'reload cdnca-control-web\n')
  result = subcommand(root, `--secret-file ${join(root, 'shared.secret')} --real-ip-header X-Forwarded-For`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(readFileSync(join(root, 'nginx.conf'), 'utf8'), once, 'rerun does not duplicate the include or key drop')
  assert.match(readFileSync(join(root, 'origin-auth.conf'), 'utf8'), /\$http_x_forwarded_for/)
  assert.equal(subcommand(root, '--real-ip-header Bogus').status === 0, false)
  assert.equal(subcommand(root, '--bogus').status === 0, false)
}))

test('origin-auth subcommand restores the previous configuration when nginx -t or reload fails', () => withRoot((root) => {
  const before = installed(root)
  writeFileSync(join(root, 'nginx-t-fails'), '')
  let result = subcommand(root)
  assert.notEqual(result.status, 0); assert.match(result.stderr, /已恢复原配置/)
  assert.equal(readFileSync(join(root, 'nginx.conf'), 'utf8'), before)
  assert.ok(!existsSync(join(root, 'origin-auth.conf')), 'new origin-auth.conf removed')
  rmSync(join(root, 'nginx-t-fails'))
  assert.equal(subcommand(root).status, 0)
  const enabled = readFileSync(join(root, 'nginx.conf'), 'utf8'), authBefore = readFileSync(join(root, 'origin-auth.conf'), 'utf8')
  writeFileSync(join(root, 'reload-fails'), '')
  result = subcommand(root, '--real-ip-header True-Client-IP')
  assert.notEqual(result.status, 0); assert.match(result.stderr, /重载 .* 失败，已恢复原配置/)
  assert.equal(readFileSync(join(root, 'nginx.conf'), 'utf8'), enabled)
  assert.equal(readFileSync(join(root, 'origin-auth.conf'), 'utf8'), authBefore, 'previous origin-auth.conf restored')
}))

test('origin-auth subcommand refuses X-Forwarded-For behind the BaoTa site proxy', () => withRoot((root) => {
  installed(root)
  const conf = join(root, 'nginx.conf')
  writeFileSync(conf, readFileSync(conf, 'utf8').replace('server_name _;', 'server_name _;\n        set_real_ip_from 127.0.0.1;\n        real_ip_header X-Real-IP;'))
  const result = subcommand(root)
  assert.notEqual(result.status, 0); assert.match(result.stderr, /宝塔环境/)
  assert.equal(subcommand(root, '--real-ip-header CF-Connecting-IP').status, 0)
}))

// gawk（Ubuntu 24.04、RHEL 系默认 awk）不允许把保留字/内建函数名当 -v 变量："cannot use gawk builtin `include' as
// variable name"，退出 2。73 实测 origin-auth 子命令因 -v include= 失败。mawk/busybox/BSD awk 不报错，所以静态全量检查。
const gawkReserved = new Set(('BEGIN END BEGINFILE ENDFILE func function if else while for do break continue next nextfile exit ' +
  'return delete getline print printf in switch case default include load namespace and asort asorti atan2 bindtextdomain ' +
  'close compl cos dcgettext dcngettext exp fflush gensub gsub index int isarray length log lshift match mkbool mktime or ' +
  'patsplit rand rshift sin split sprintf sqrt srand strftime strtonum sub substr system systime tolower toupper typeof xor').split(' '))
test('scripts/: no awk -v variable is a gawk reserved word or builtin', () => {
  const root = new URL('../scripts/', import.meta.url)
  const listed = spawnSync('git', ['ls-files', '*.sh'], { cwd: root, encoding: 'utf8' })
  assert.equal(listed.status, 0, listed.stderr)
  const hits = []
  for (const file of listed.stdout.split('\n').filter(Boolean)) {
    // 不限定在 awk 同一行：多行 awk 调用里 -v 可能换行续写；其他命令的 -v X=（如 psql -v ON_ERROR_STOP=1）不会撞保留字。
    for (const [, name] of readFileSync(new URL(file, root), 'utf8').matchAll(/(?<=\s)-v\s+([A-Za-z_][A-Za-z0-9_]*)=/g)) {
      if (gawkReserved.has(name)) hits.push(`${file}: -v ${name}=`)
    }
  }
  assert.deepEqual(hits, [])
})

// 真 gawk 跑子命令；本机（macOS）默认无 gawk，跳过并由上面的静态检查兜底。CDNCA_TEST_GAWK 可指定路径。
const gawk = process.env.CDNCA_TEST_GAWK || spawnSync('sh', ['-c', 'command -v gawk'], { encoding: 'utf8' }).stdout.trim()
test('origin-auth subcommand works when awk is gawk', { skip: gawk ? false : '本机没有 gawk（macOS 默认 BSD awk），由静态检查覆盖' },
  () => withRoot((root) => {
    // 先确认这个 gawk 确实拒绝旧写法 -v include=，否则用例证明不了什么。
    assert.equal(spawnSync(gawk, ['-v', 'include=x', 'BEGIN{}'], { encoding: 'utf8' }).status, 2)
    installed(root)
    const result = shell(root, [`awk() { command ${JSON.stringify(gawk)} "$@"; }`,
      `systemctl() { :; }`,
      block('origin_auth_main').replace('"/etc/systemd/system/${WEB_SERVICE_NAME}.service"', '"$CONFIG_DIR/web.service"'),
      'origin_auth_main --real-ip-header CF-Connecting-IP'].join('\n'))
    assert.equal(result.status, 0, result.stderr)
    const config = readFileSync(join(root, 'nginx.conf'), 'utf8')
    assert.ok(config.includes(`    include ${join(root, 'origin-auth.conf')};`))
    assert.equal(proxyBodies(config).filter((body) => body.includes('$cdnca_client_ip')).length, 5)
  }))

function get(root, headers) {
  return new Promise((resolve, reject) => {
    const call = request({ socketPath: join(root, 'public.sock'), servername: 'localhost', ca: readFileSync(join(root, 'server.crt')),
      path: '/v1/whoami', agent: false, headers }, (response) => {
      let text = ''; response.setEncoding('utf8'); response.on('data', (chunk) => { text += chunk })
      response.on('end', () => resolve(text)); response.on('error', reject)
    })
    call.on('error', reject); call.end()
  })
}

test('real nginx: -t passes and the upstream sees the CDN client only with the origin key',
  { skip: !nginxBinary && 'set CDNCA_TEST_NGINX_BIN=/usr/sbin/nginx for the real nginx origin-auth test', timeout: 20000 }, async (t) => {
    const root = realpathSync(mkdtempSync('/tmp/cdnca-origin-auth.'))
    let child
    const upstream = createServer((incoming, outgoing) => {
      outgoing.writeHead(200, { 'Content-Type': 'application/json' })
      outgoing.end(JSON.stringify({ real: incoming.headers['x-real-ip'], xff: incoming.headers['x-forwarded-for'], key: incoming.headers['x-cdnca-origin-key'] ?? null }))
    })
    t.after(async () => { child?.kill('SIGTERM'); upstream.close(); rmSync(root, { recursive: true, force: true }) })
    assert.equal(spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-keyout', join(root, 'server.key'), '-out', join(root, 'server.crt')], { encoding: 'utf8' }).status, 0)
    writeFileSync(join(root, 'mime.types'), 'types { text/html html; }\n'); writeFileSync(join(root, 'plan-source.conf'), '')
    const { nginx } = renderInstall(root)
    writeFileSync(join(root, 'nginx.conf'), nginx
      .replace('include /etc/nginx/mime.types;', `include ${root}/mime.types;\n    access_log off;`)
      .replace('include /etc/cdnca-upgrade/plan-source-nginx.conf;', `include ${root}/plan-source.conf;`)
      .replace('listen 8443 ssl http2;', `listen unix:${root}/public.sock ssl;`)
      .replaceAll('http://127.0.0.1:8080', `http://unix:${root}/upstream.sock:`))
    await new Promise((resolve, reject) => upstream.once('error', reject).listen(join(root, 'upstream.sock'), resolve))
    const args = ['-e', 'stderr', '-p', join(root, 'runtime'), '-c', join(root, 'nginx.conf')]
    spawnSync('mkdir', ['-p', join(root, 'runtime')])
    const syntax = spawnSync(nginxBinary, ['-t', ...args], { encoding: 'utf8' })
    assert.equal(syntax.status, 0, syntax.stderr)
    child = spawn(nginxBinary, [...args, '-g', 'daemon off; master_process off;'], { stdio: 'ignore' })
    let seen
    for (let i = 0; i < 200 && !seen; i++) { try { seen = JSON.parse(await get(root, {})) } catch { await delay(25) } }
    assert.ok(seen, 'nginx did not start')
    // unix socket 的 $remote_addr 是 "unix:"。
    assert.deepEqual(seen, { real: 'unix:', xff: 'unix:', key: null })
    const viaCDN = JSON.parse(await get(root, { 'X-Cdnca-Origin-Key': secret, 'X-Forwarded-For': '10.9.9.9, 203.0.113.9' }))
    assert.deepEqual(viaCDN, { real: '203.0.113.9', xff: '203.0.113.9', key: null })
    const forged = JSON.parse(await get(root, { 'X-Cdnca-Origin-Key': 'wrong', 'X-Forwarded-For': '203.0.113.9', 'X-Real-IP': '203.0.113.9' }))
    assert.deepEqual(forged, { real: 'unix:', xff: 'unix:', key: null })
  })

test('fresh install: parse_args rejects an unknown header, the BaoTa environment rejects X-Forwarded-For', () => withRoot((root) => {
  const parse = [block('valid_port'), block('parse_args'), block('resolve_install_env')].join('\n')
  let result = shell(root, `${parse}\nparse_args --origin-auth --real-ip-header X-Client-IP`)
  assert.notEqual(result.status, 0); assert.match(result.stderr, /--real-ip-header 只支持/)
  result = shell(root, `${parse}\nparse_args --origin-auth --real-ip-header CF-Connecting-IP; printf '%s %s' "$ORIGIN_AUTH" "$REAL_IP_HEADER"`)
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout, 'true CF-Connecting-IP')
  const bt = `bt_detect() { return 0; }\nINSTALL_ENV=bt WEB_PORT='' BT_PROXY=false`
  result = shell(root, `${parse}\n${bt}\nparse_args --origin-auth; resolve_install_env`)
  assert.notEqual(result.status, 0); assert.match(result.stderr, /宝塔环境/)
  assert.equal(shell(root, `${parse}\n${bt}\nparse_args --origin-auth --real-ip-header True-Client-IP; resolve_install_env`).status, 0)
  assert.equal(shell(root, `${parse}\n${bt}\nparse_args; resolve_install_env`).status, 0, 'without --origin-auth nothing changes')
}))
