import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

test('control API trusts only the loopback nginx as the client-address proxy', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-control-client-ip-'))
  try {
    const result = spawnSync('bash', ['-c', [
      'set -Eeuo pipefail', ...source.match(/^readonly UPGRADE_[A-Z_]+=.*$/gm), block('fail'),
      block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'),
      'generate_runtime_secrets', 'write_environment',
    ].join('\n')], { encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory, KEY_DIR: directory,
      PKI_DIR: directory, DATABASE_URL: 'postgresql://localhost/test', REDIS_URL: 'redis://localhost/0',
      NATS_URL: 'nats://localhost:4222', LICENSING_SERVER: 'https://auth.example.test',
      INSTALLATION_ID: 'test-installation', INSTALLATION_NAME: 'test', CONTROL_VERSION: '1.0.1',
      DOWNLOAD_DIR: join(directory, 'downloads'), CONTROL_ORIGIN: 'https://control.example.test', DATA_DIR: directory,
    } })
    assert.equal(result.status, 0, result.stderr)
    const lines = readFileSync(join(directory, 'control.env'), 'utf8').trim().split('\n')
    const trusted = lines.filter((line) => line.startsWith('API_KEY_TRUSTED_PROXY_CIDRS='))
    assert.deepEqual(trusted, ['API_KEY_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128'])
    assert.equal(lines.find((line) => line.startsWith('HTTP_ADDR=')), 'HTTP_ADDR=127.0.0.1:8080')
  } finally { rmSync(directory, { recursive: true }) }
})

test('every nginx API proxy replaces client forwarding headers with the TCP peer address', () => {
  const config = block('write_nginx_config')
  const proxies = [...config.matchAll(/location [^{]*\{((?:(?!\n        \})[\s\S])*?proxy_pass http:\/\/127\.0\.0\.1:8080;)/g)]
    .map((match) => match[1]).filter((body) => body.includes('proxy_set_header'))
  // brand favicon/logo/login_ad, /v1/auth/ (gzip off) and /v1/
  assert.equal(proxies.length, 5)
  for (const body of proxies) {
    assert.match(body, /proxy_set_header X-Real-IP \\\$remote_addr;/)
    assert.match(body, /proxy_set_header X-Forwarded-For \\\$remote_addr;/)
    assert.doesNotMatch(body, /proxy_add_x_forwarded_for/)
    assert.doesNotMatch(body, /proxy_set_header Forwarded\b/)
  }
  assert.doesNotMatch(config, /proxy_add_x_forwarded_for/)
})
