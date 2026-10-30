import assert from 'node:assert/strict'
import { spawn, spawnSync } from './helpers/large-bash-script.mjs'
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { request } from 'node:https'
import { isAbsolute, join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const writer = source.match(/^write_nginx_config\(\) \{[\s\S]*?^\}\n\n(?=setup_web\(\))/m)?.[0]
// write_nginx_config picks the nginx binary and mime.types through these (fix-btenv).
const nginxHelpers = ['control_nginx_bin', 'control_nginx_mime_types'].map((name) =>
  source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}$`, 'm'))?.[0]).join('\n')
const nginxBinary = process.env.CDNCA_TEST_NGINX_BIN
const batchPaths = ['/v1/nodes/metrics/latest', '/v1/nodes/monitoring/latest']
const largeJSON = JSON.stringify({ token: 'x'.repeat(4096) })
const hashedAsset = `/* ${'console.log("compressible");'.repeat(200)} */`
const securityHeaders = { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'strict-origin-when-cross-origin' }
const query = new URLSearchParams(Array.from({ length: 300 }, (_, index) =>
  ['node_id', `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`])).toString()

function renderManagementNginxConfig(root) {
  assert.ok(writer, 'extract only the real nginx writer, never the installer main')
  const configuration = join(root, 'nginx.conf')
  const result = spawnSync('bash', ['-c', [
    'set -Eeuo pipefail',
    // This render-only test does not claim nginx syntax validation.
    'nginx() { [[ "$#" -eq 5 && "$1" == -t && "$2" == -c && "$3" == "$NGINX_CONF" && "$4" == -p && "$5" == "$NGINX_RUNTIME_DIR" ]]; }',
    nginxHelpers, writer, 'write_nginx_config',
  ].join('\n')], { encoding: 'utf8', timeout: 5000, env: {
    ...process.env, NGINX_CONF: configuration, NGINX_RUNTIME_DIR: join(root, 'runtime'),
    MASTER_PORT: '8443', WEB_LISTEN: '8443', WEB_REAL_IP: '', INSTALL_ENV: 'plain', BT_ROOT: '', WEB_ROOT: root, DATA_DIR: root, NATIVE_ROOT: root, DOWNLOAD_DIR: join(root, 'downloads'),
    PUBLIC_CERT_PATH: join(root, 'server.crt'), PUBLIC_KEY_PATH: join(root, 'server.key'),
  } })
  assert.equal(result.status, 0, result.stderr)
  return readFileSync(configuration, 'utf8')
}

function requestManagementProxy(root, path, method = 'GET', body = '', extra = {}) {
  return new Promise((resolve, reject) => {
    const call = request({ socketPath: join(root, 'public.sock'), servername: 'localhost',
      ca: readFileSync(join(root, 'server.crt')), path, method, agent: false,
      headers: { ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}), ...extra },
    }, (response) => {
      let text = ''
      response.setEncoding('utf8')
      response.on('data', (chunk) => { text += chunk })
      response.on('end', () => resolve({ status: response.statusCode, body: text, headers: response.headers }))
      response.on('error', reject)
    })
    call.on('error', reject)
    call.setTimeout(2000, () => call.destroy(new Error('isolated nginx request timed out')))
    call.end(body)
  })
}

async function startIsolatedManagementNginx(t) {
  assert.ok(isAbsolute(nginxBinary), 'CDNCA_TEST_NGINX_BIN must name an existing real nginx binary')
  const root = realpathSync(mkdtempSync('/tmp/cdnca-nginx-line.'))
  const seen = []
  let child, exited
  const upstream = createServer((incoming, outgoing) => {
    let body = ''
    incoming.on('data', (chunk) => { body += chunk })
    incoming.on('end', () => {
      seen.push({ path: incoming.url, method: incoming.method, body })
      if (incoming.url === '/v1/brand-assets/logo') {
        outgoing.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=300' })
        outgoing.end('uploaded logo')
      } else if (incoming.url === '/v1/brand-assets/favicon') {
        outgoing.writeHead(404, { 'Content-Type': 'application/json' })
        outgoing.end('{"code":"not_found"}')
      } else if (incoming.url === '/v1/auth/refresh' || incoming.url === '/v1/large-fixture') {
        outgoing.writeHead(200, { 'Content-Type': 'application/json' })
        outgoing.end(largeJSON)
      } else {
        outgoing.writeHead(401, { 'Content-Type': 'application/json' })
        outgoing.end('{"code":"invalid_session"}')
      }
    })
  })
  t.after(async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGQUIT')
      const forced = setTimeout(() => child.kill('SIGKILL'), 3000)
      await exited
      clearTimeout(forced)
    }
    if (upstream.listening) {
      upstream.closeAllConnections()
      await new Promise((resolve, reject) => upstream.close((error) => error ? reject(error) : resolve()))
    }
    if (child?.pid) assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' }, 'owned nginx must exit before cleanup')
    rmSync(root, { recursive: true })
  })
  const cert = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', join(root, 'server.key'), '-out', join(root, 'server.crt')],
  { encoding: 'utf8', timeout: 10000 })
  assert.equal(cert.status, 0, 'isolated TLS certificate generation failed')
  writeFileSync(join(root, 'mime.types'), 'types { text/html html; application/javascript js; image/png png; }\n')
  writeFileSync(join(root, 'plan-source.conf'), '')
  writeFileSync(join(root, 'index.html'), 'isolated management web\n')
  writeFileSync(join(root, 'runtime-config.js'), 'window.__FIXTURE__ = true\n')
  writeFileSync(join(root, 'logo.png'), 'bundled logo')
  mkdirSync(join(root, 'site'))
  writeFileSync(join(root, 'site', 'index.html'), 'isolated public website\n')
  mkdirSync(join(root, 'assets'))
  writeFileSync(join(root, 'assets', 'app-AbCdEf12.js'), hashedAsset)
  // Only replace deployment paths/listeners with owned sockets and fixtures.
  // Keep the generated buffer, routing, proxy, methods and security headers intact.
  const rendered = renderManagementNginxConfig(root)
  for (const fixed of ['include /etc/nginx/mime.types;', 'include /etc/cdnca-upgrade/plan-source-nginx.conf;', 'listen 8443 ssl http2;']) {
    assert.equal(rendered.split(fixed).length, 2, `exactly one replaceable ${fixed}`)
  }
  const configuration = rendered
    .replace('include /etc/nginx/mime.types;', `include ${root}/mime.types;\n    access_log off;`)
    .replace('include /etc/cdnca-upgrade/plan-source-nginx.conf;', `include ${root}/plan-source.conf;`)
    .replace('listen 8443 ssl http2;', `listen unix:${root}/public.sock ssl http2;`)
    .replaceAll('http://127.0.0.1:8080', `http://unix:${root}/upstream.sock:`)
  writeFileSync(join(root, 'nginx.conf'), configuration)
  await new Promise((resolve, reject) => upstream.once('error', reject).listen(join(root, 'upstream.sock'), resolve))
  const arguments_ = ['-e', 'stderr', '-p', join(root, 'runtime'), '-c', join(root, 'nginx.conf')]
  const syntax = spawnSync(nginxBinary, ['-t', ...arguments_], { encoding: 'utf8', timeout: 5000 })
  assert.equal(syntax.status, 0, syntax.stderr)
  let stderr = '', spawnError
  child = spawn(nginxBinary, [...arguments_, '-g', 'daemon off; master_process off;'], { stdio: ['ignore', 'ignore', 'pipe'] })
  child.stderr.on('data', (chunk) => { stderr += chunk })
  exited = new Promise((resolve) => {
    child.once('exit', resolve)
    child.once('error', (error) => { spawnError = error; resolve() })
  })
  const deadline = performance.now() + 5000
  while (performance.now() < deadline) {
    assert.ifError(spawnError)
    assert.equal(child.exitCode, null, stderr)
    try {
      const ready = await requestManagementProxy(root, '/healthz')
      assert.equal(ready.status, 200)
      return { root, seen }
    } catch { await delay(25) }
  }
  assert.fail(`isolated nginx readiness failed: ${stderr}`)
}

test('actual management nginx generation bounds each request line at 16k for both 300-node batches', () => {
  const root = realpathSync(mkdtempSync('/tmp/cdnca-nginx-line.'))
  try {
    const configuration = renderManagementNginxConfig(root)
    assert.match(configuration, /http \{\s+large_client_header_buffers 4 16k;/)
    assert.equal(configuration.match(/\blarge_client_header_buffers\b/g)?.length, 1)
    for (const path of batchPaths) {
      const bytes = Buffer.byteLength(`GET ${path}?${query} HTTP/1.1\r\n`)
      assert.ok(bytes > 8192 && bytes < 16384, `${path}: ${bytes} bytes`)
    }
    assert.match(configuration, /location \^~ \/v1\/ \{[\s\S]*?proxy_pass http:\/\/127\.0\.0\.1:8080;/)
    assert.match(configuration, /location = \/v1\/internal \{ return 404; \}/)
    assert.match(configuration, /location \^~ \/v1\/internal\/ \{ return 404; \}/)
  } finally { rmSync(root, { recursive: true }) }
})

test('real isolated nginx preserves 401/proxy semantics and rejects over-16k lines',
  { skip: !nginxBinary && 'set CDNCA_TEST_NGINX_BIN=/usr/sbin/nginx for real isolated TLS/socket tests', timeout: 20000 }, async (t) => {
    const { root, seen } = await startIsolatedManagementNginx(t)
    for (const path of batchPaths) {
      await t.test(`${path}: 300 canonical IDs reach the unauthenticated upstream unchanged`, async () => {
        const target = `${path}?${query}`
        const response = await requestManagementProxy(root, target)
        assert.equal(response.status, 401)
        assert.equal(response.body, '{"code":"invalid_session"}')
        assert.equal(response.headers['cache-control'], 'no-store')
        assert.deepEqual(seen.at(-1), { path: target, method: 'GET', body: '' })
      })
      await t.test(`${path}: over-16k request line is refused before upstream`, async () => {
        const before = seen.length
        const response = await requestManagementProxy(root, `${path}?${query}&padding=${'x'.repeat(4096)}`)
        assert.equal(response.status, 414)
        assert.equal(seen.length, before)
      })
    }
    await t.test('short requests and non-GET methods retain their upstream 401', async () => {
      for (const method of ['GET', 'POST']) {
        const body = method === 'POST' ? '{"fixture":true}' : ''
        const response = await requestManagementProxy(root, '/v1/nodes', method, body)
        assert.equal(response.status, 401)
        assert.deepEqual(seen.at(-1), { path: '/v1/nodes', method, body })
      }
    })
    await t.test('public health/static paths work and private API remains denied', async () => {
      const before = seen.length
      assert.equal((await requestManagementProxy(root, '/healthz')).status, 200)
      assert.equal((await requestManagementProxy(root, '/dashboard/')).body, 'isolated management web\n')
      // /dashboard without the trailing slash is the console too, not the website shell (10-27).
      assert.equal((await requestManagementProxy(root, '/dashboard')).body, 'isolated management web\n')
      assert.equal((await requestManagementProxy(root, '/pricing')).body, 'isolated public website\n')
      for (const path of ['/v1/internal', '/v1/internal/control-upgrade-plan']) {
        assert.equal((await requestManagementProxy(root, path)).status, 404)
      }
      assert.equal(seen.length, before)
    })
    await t.test('only successful content-hashed assets are immutable and compressible responses are gzipped', async () => {
      const gzip = { 'Accept-Encoding': 'gzip' }
      for (const path of ['/dashboard/assets/app-AbCdEf12.js', '/assets/app-AbCdEf12.js']) {
        const asset = await requestManagementProxy(root, path, 'GET', '', gzip)
        assert.equal(asset.status, 200, path)
        assert.equal(asset.headers['cache-control'], 'public, max-age=31536000, immutable', path)
        assert.equal(asset.headers['content-encoding'], 'gzip', path)
        assert.match(asset.headers.vary ?? '', /Accept-Encoding/, path)
        for (const [name, value] of Object.entries(securityHeaders)) assert.equal(asset.headers[name], value, `${path} ${name}`)
      }
      const missing = await requestManagementProxy(root, '/dashboard/assets/app-Missing0.js')
      assert.equal(missing.status, 404)
      assert.equal(missing.headers['cache-control'], 'no-store', 'a missing hashed asset must never be cached as immutable')
      for (const path of ['/dashboard/', '/', '/runtime-config.js', '/dashboard/runtime-config.js']) {
        const response = await requestManagementProxy(root, path)
        assert.equal(response.status, 200, path)
        assert.equal(response.headers['cache-control'], 'no-store', path)
      }
      const plain = await requestManagementProxy(root, '/v1/large-fixture', 'GET', '', gzip)
      assert.equal(plain.headers['content-encoding'], 'gzip', 'ordinary API JSON is compressed')
      assert.equal(plain.headers['cache-control'], 'no-store')
      const auth = await requestManagementProxy(root, '/v1/auth/refresh', 'POST', '{}', gzip)
      assert.equal(auth.status, 200)
      assert.equal(auth.headers['content-encoding'], undefined, 'token-bearing auth responses are never compressed')
      assert.equal(auth.body, largeJSON)
      assert.equal(auth.headers['cache-control'], 'no-store')
    })
    await t.test('brand assets keep the upstream cache policy and fall back as no-store', async () => {
      const uploaded = await requestManagementProxy(root, '/v1/brand-assets/logo')
      assert.equal(uploaded.status, 200)
      assert.equal(uploaded.body, 'uploaded logo')
      assert.equal(uploaded.headers['cache-control'], 'public, max-age=300')
      for (const [name, value] of Object.entries(securityHeaders)) assert.equal(uploaded.headers[name], value, name)
      const fallback = await requestManagementProxy(root, '/v1/brand-assets/favicon')
      assert.equal(fallback.status, 200)
      assert.equal(fallback.body, 'bundled logo')
      assert.equal(fallback.headers['cache-control'], 'no-store')
    })
  })
