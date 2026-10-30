import assert from 'node:assert/strict'
import { spawn, spawnSync } from './helpers/large-bash-script.mjs'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer } from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test, { after, before } from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const denial = 'cdnca: 本机公网 IP 198.51.100.66 未登记为主控 IP，无法下载主控安装包。请在授权门户确认主控 IP。\n'
let material, certificate, tls

function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

before(() => {
  material = mkdtempSync(join(tmpdir(), 'cdnca-master-ip-tls-'))
  const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1', '-keyout', join(material, 'k.pem'), '-out', join(material, 'c.pem')], { encoding: 'utf8' })
  assert.equal(result.status, 0)
  certificate = join(material, 'c.pem')
  tls = { key: readFileSync(join(material, 'k.pem')), cert: readFileSync(certificate) }
})
after(() => { if (material) rmSync(material, { recursive: true }) })

async function server(t, status, body, contentType = 'text/plain; charset=utf-8') {
  const instance = createServer(tls, (request, response) => {
    response.setHeader('Connection', 'close')
    response.setHeader('Content-Type', contentType)
    response.statusCode = status
    response.end(body)
  })
  await new Promise((resolve) => instance.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => { instance.close(resolve); instance.closeAllConnections() }))
  return `https://127.0.0.1:${instance.address().port}`
}

function run(script, directory) {
  return new Promise((resolve, reject) => {
    const child = spawn('bash', ['-c', ['set -Eeuo pipefail', ...script].join('\n')], { timeout: 10000, env: {
      ...process.env, NO_PROXY: '127.0.0.1', no_proxy: '127.0.0.1', HTTPS_PROXY: '', https_proxy: '',
      CURL_CA_BUNDLE: certificate, TEMP_DIR: directory } })
    let stdout = '', stderr = ''
    child.stdout.on('data', (data) => { stdout += data })
    child.stderr.on('data', (data) => { stderr += data })
    child.once('error', reject)
    child.once('close', (code) => resolve({ code, stdout, stderr }))
  })
}

const probe = ['log', 'fail', 'check_master_download_authorization'].map(block)

test('403 from every download origin explains the master IP registration in Chinese', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-master-ip-'))
  t.after(() => rmSync(directory, { recursive: true }))
  const primary = await server(t, 403, denial), fallback = await server(t, 403, denial)
  const result = await run([...probe, `check_master_download_authorization '${primary}/SHA256SUMS' '${fallback}/SHA256SUMS'`,
    'echo continued'], directory)
  assert.notEqual(result.code, 0)
  assert.match(result.stderr, /授权服务器拒绝向本机下载主控安装包（HTTP 403）/)
  assert.match(result.stderr, /授权服务器看到的本机公网 IP：198\.51\.100\.66/)
  assert.match(result.stderr, /请在授权门户“我的授权”确认主控 IP/)
  assert.match(result.stderr, /master_download_ip_not_registered/)
  assert.ok(!result.stdout.includes('continued'))
})

test('an authorized origin or a non-403 failure is left to the normal download path', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-master-ip-'))
  t.after(() => rmSync(directory, { recursive: true }))
  const denied = await server(t, 403, denial), allowed = await server(t, 200, 'sums\n'), broken = await server(t, 502, 'x')
  for (const urls of [[denied, allowed], [allowed, allowed], [broken, broken]]) {
    const result = await run([...probe, `check_master_download_authorization '${urls[0]}/S' '${urls[1]}/S'`, 'echo continued'], directory)
    assert.equal(result.code, 0, result.stderr)
    assert.match(result.stdout, /continued/)
  }
})

test('activation refused for master_ip_mismatch prints the registration hint', () => {
  const body = block('activate')
  const hint = body.indexOf('.code == "master_ip_mismatch"')
  assert.ok(hint > 0 && hint < body.indexOf("fail 'activation_issuer_rejected'"))
  assert.match(body, /本机公网 IP 与授权登记的主控 IP 不一致，激活被拒绝（激活码未被消耗）/)
})

test('the master package probe runs before any native download', () => {
  const body = block('download_native_support')
  const probeAt = body.indexOf('check_master_download_authorization "$CONTROL_NATIVE_SHA256_URL"')
  assert.ok(probeAt > 0 && probeAt < body.indexOf('download_json_verified'))
})
