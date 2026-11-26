// 「源IP请求头」（control-api internal/clientip）：管理端 nginx 把 X-Real-IP /
// X-Forwarded-For 改写成 TCP 对端，客户端原值紧跟其后以 X-Cdnca-Client-X-Real-IP / X-Cdnca-Client-X-Forwarded-For
// 转给 control-api；proxy_set_header 同名即替换，客户端自带的这两个内部头到不了 control-api。
// origin-auth 改写（origin_auth_apply_nginx）保留并补上这两行。真实 nginx 用例需 CDNCA_TEST_NGINX_BIN。
import assert from 'node:assert/strict'
import { spawn, spawnSync } from './helpers/large-bash-script.mjs'
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
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
const helpers = ['log', 'fail', 'origin_auth_apply_nginx', 'control_nginx_bin', 'control_nginx_mime_types', 'node_download_server']
  .map(block).join('\n') + '\n' +
  // heredoc 里有顶格的 }，按下一个函数定界（同 install-control-origin-auth.test.mjs）。
  source.match(/^write_nginx_config\(\) \{[\s\S]*?^\}\n\n(?=# 验证节点升级下载端点)/m)[0]
const nginxBinary = process.env.CDNCA_TEST_NGINX_BIN
const clientLines = '            proxy_set_header X-Cdnca-Client-X-Real-IP \\$http_x_real_ip;\n' +
  '            proxy_set_header X-Cdnca-Client-X-Forwarded-For \\$http_x_forwarded_for;\n'

function render(root, script = 'write_nginx_config') {
  const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'nginx() { :; }', helpers, script].join('\n')], { encoding: 'utf8', timeout: 10000, env: {
    ...process.env, CONFIG_DIR: root, NGINX_CONF: join(root, 'nginx.conf'), NGINX_RUNTIME_DIR: join(root, 'runtime'),
    ORIGIN_AUTH_CONF: join(root, 'origin-auth.conf'), MASTER_PORT: '8443', WEB_LISTEN: '8443', WEB_REAL_IP: '', INSTALL_ENV: 'plain',
    WEB_ROOT: root, DATA_DIR: root, NATIVE_ROOT: root, DOWNLOAD_DIR: join(root, 'downloads'), PUBLIC_CERT_PATH: join(root, 'server.crt'),
    PUBLIC_KEY_PATH: join(root, 'server.key'), ORIGIN_AUTH: 'false',
  } })
  assert.equal(result.status, 0, result.stderr)
  return readFileSync(join(root, 'nginx.conf'), 'utf8')
}
function withRoot(run) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-source-ip-')))
  try { return run(root) } finally { rmSync(root, { recursive: true, force: true }) }
}
// location 自身（12 格缩进）的 proxy_pass；/v1/ 里嵌套的 gzip location 继承外层请求头。
function proxyBodies(config) {
  return [...config.matchAll(/location [^{]*\{((?:(?!\n        \})[\s\S])*?\n {12}proxy_pass http:\/\/127\.0\.0\.1:8080;)/g)]
    .map((match) => match[1]).filter((body) => body.includes('proxy_set_header'))
}

test('every control-api proxy passes the client X-Real-IP / X-Forwarded-For as internal headers', () => {
  const config = source.match(/^write_nginx_config\(\) \{[\s\S]*?^\}\n\n(?=# 验证节点升级下载端点)/m)[0]
  const proxies = proxyBodies(config)
  assert.equal(proxies.length, 5)
  for (const body of proxies) {
    assert.ok(body.includes('            proxy_set_header Forwarded "";\n            proxy_set_header X-Forwarded-For \\$remote_addr;\n' + clientLines), body)
  }
  // 每处规范 XFF 后都有（含 /agent/v1/），别处没有。
  assert.equal(config.split(clientLines).length - 1, config.split('proxy_set_header X-Forwarded-For \\$remote_addr;\n').length - 1)
})

test('origin-auth keeps the internal headers after its verified line and adds them to older hosts', () => withRoot((root) => {
  const fresh = render(root)
  const plainLines = clientLines.replaceAll('\\$', '$')
  assert.equal(proxyBodies(fresh).filter((body) => body.includes(plainLines)).length, 5)
  const applied = render(root, 'write_nginx_config\norigin_auth_apply_nginx "$NGINX_CONF"')
  const verified = '            proxy_set_header X-Cdnca-Origin-Verified $cdnca_origin_verified;\n'
  assert.equal(applied.split(verified + plainLines).length - 1, 6)
  assert.equal(applied.split('X-Cdnca-Client-X-Real-IP').length - 1, 6)
  // a host from before the rule: origin-auth adds them once; a re-run changes nothing
  writeFileSync(join(root, 'nginx.conf'), applied.replaceAll(plainLines, ''))
  assert.equal(render(root, 'origin_auth_apply_nginx "$NGINX_CONF"'), applied)
  assert.equal(render(root, 'origin_auth_apply_nginx "$NGINX_CONF"'), applied)
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

test('real nginx: control-api gets the client originals and never a client-sent internal header',
  { skip: !nginxBinary && 'set CDNCA_TEST_NGINX_BIN=/usr/sbin/nginx for the real nginx source IP header test', timeout: 20000 }, async (t) => {
    const root = realpathSync(mkdtempSync('/tmp/cdnca-source-ip.'))
    let child
    const upstream = createServer((incoming, outgoing) => {
      outgoing.writeHead(200, { 'Content-Type': 'application/json' })
      outgoing.end(JSON.stringify({ real: incoming.headers['x-real-ip'], xff: incoming.headers['x-forwarded-for'],
        cf: incoming.headers['cf-connecting-ip'] ?? null,
        clientReal: incoming.headers['x-cdnca-client-x-real-ip'] ?? null, clientXFF: incoming.headers['x-cdnca-client-x-forwarded-for'] ?? null }))
    })
    t.after(async () => { child?.kill('SIGTERM'); upstream.close(); rmSync(root, { recursive: true, force: true }) })
    assert.equal(spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-keyout', join(root, 'server.key'), '-out', join(root, 'server.crt')], { encoding: 'utf8' }).status, 0)
    writeFileSync(join(root, 'mime.types'), 'types { text/html html; }\n'); writeFileSync(join(root, 'plan-source.conf'), '')
    const nginx = render(root)
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
    // unix socket 的 $remote_addr 是 "unix:"；客户端没带原值时内部头不发送。
    assert.deepEqual(seen, { real: 'unix:', xff: 'unix:', cf: null, clientReal: null, clientXFF: null })
    // 经 CDN：原值进内部头，CF-Connecting-IP 原样透传，规范头仍是 TCP 对端
    const viaCDN = JSON.parse(await get(root, { 'X-Real-IP': '203.0.113.3', 'X-Forwarded-For': '203.0.113.4, 198.51.100.9',
      'CF-Connecting-IP': '203.0.113.1' }))
    assert.deepEqual(viaCDN, { real: 'unix:', xff: 'unix:', cf: '203.0.113.1', clientReal: '203.0.113.3', clientXFF: '203.0.113.4, 198.51.100.9' })
    // 客户端自带的内部头被替换：没有原值时整个丢弃，有原值时只剩原值
    const forged = JSON.parse(await get(root, { 'X-Cdnca-Client-X-Real-IP': '192.0.2.66', 'X-Cdnca-Client-X-Forwarded-For': '192.0.2.67' }))
    assert.deepEqual(forged, { real: 'unix:', xff: 'unix:', cf: null, clientReal: null, clientXFF: null })
    const both = JSON.parse(await get(root, { 'X-Cdnca-Client-X-Real-IP': '192.0.2.66', 'X-Real-IP': '203.0.113.3' }))
    assert.deepEqual(both, { real: 'unix:', xff: 'unix:', cf: null, clientReal: '203.0.113.3', clientXFF: null })
  })
