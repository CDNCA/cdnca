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

const environmentTemplate = block('write_environment')
const placeholders = [...new Set([...environmentTemplate.matchAll(/\$\{([A-Z_0-9]+)\}/g)].map((match) => match[1]))]
  .filter((name) => !name.endsWith('_BASE64') && !['ACCESS_TOKEN_SECRET', 'CONFIG_DIR'].includes(name))
  .map((name) => `${name}=placeholder`)
const prelude = ['set -Eeuo pipefail', block('fail'), 'log() { :; }', ...placeholders,
  block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'),
  block('local_gateway_environment'), 'GATEWAY_HOST=console.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443',
  environmentTemplate]

function renderEnvironment() {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-account-recovery-'))
  try {
    const result = spawnSync('bash', ['-c', [...prelude,
      'CONTROL_DOMAIN=console.example.test CONTROL_ORIGIN=https://console.example.test',
      'generate_runtime_secrets', 'write_environment'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory },
    })
    assert.equal(result.status, 0, result.stderr)
    const text = readFileSync(join(directory, 'control.env'), 'utf8')
    return Object.fromEntries(text.trim().split('\n').map((line) => {
      const index = line.indexOf('=')
      return [line.slice(0, index), line.slice(index + 1).replace(/^'(.*)'$/, '$1')]
    }))
  } finally {
    rmSync(directory, { recursive: true })
  }
}

function decodeKey(value, name) {
  assert.match(value, /^[A-Za-z0-9+/]{43}=$/, `${name} must use canonical padded base64`)
  const decoded = Buffer.from(value, 'base64')
  assert.equal(decoded.length, 32, `${name} must contain 32 bytes`)
  assert.equal(decoded.toString('base64'), value, `${name} must round-trip`)
  return decoded
}

test('fresh installation enables account recovery with an independent keyring and platform context', () => {
  const environment = renderEnvironment()
  assert.equal(environment.ACCOUNT_RECOVERY_ENABLED, 'true')
  assert.equal(environment.ACCOUNT_RECOVERY_BASE_URL, 'https://console.example.test/dashboard/reset-password')
  assert.equal(environment.ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID, 'account_recovery_email')
  assert.equal(environment.ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION, '1')
  assert.equal(environment.ACCOUNT_RECOVERY_TRUSTED_PROXY_CIDRS, '127.0.0.1/32,::1/128')
  assert.equal(environment.ACCOUNT_RECOVERY_PLATFORM_HOSTS, 'console.example.test')

  const hmacKey = decodeKey(environment.ACCOUNT_RECOVERY_HMAC_KEY_BASE64, 'recovery HMAC key')
  assert.equal(environment.ACCOUNT_RECOVERY_KEK_ACTIVE_KEY_ID, 'account-recovery-v1')
  const keyring = JSON.parse(environment.ACCOUNT_RECOVERY_KEK_KEYS_JSON)
  assert.deepEqual(Object.keys(keyring), ['account-recovery-v1'])
  const kek = decodeKey(keyring['account-recovery-v1'], 'recovery KEK')
  assert.notDeepEqual(hmacKey, kek, 'HMAC and encryption keys must be independent')
})

test('each fresh installation gets independent account recovery secrets', () => {
  const first = renderEnvironment()
  const second = renderEnvironment()
  assert.notEqual(first.ACCOUNT_RECOVERY_HMAC_KEY_BASE64, second.ACCOUNT_RECOVERY_HMAC_KEY_BASE64)
  assert.notEqual(first.ACCOUNT_RECOVERY_KEK_KEYS_JSON, second.ACCOUNT_RECOVERY_KEK_KEYS_JSON)
})
