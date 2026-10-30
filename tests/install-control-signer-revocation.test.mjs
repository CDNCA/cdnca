import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
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

function render(env) {
  const script = ['set -Eeuo pipefail', source.match(/^fail\(\) .*$/m)[0],
    block('signer_revocation_environment'), 'signer_revocation_environment'].join('\n')
  return spawnSync('bash', ['-c', script], { encoding: 'utf8', env: {
    PATH: process.env.PATH, LICENSING_SERVER: 'https://auth.example', DOWNLOAD_DIR: '/var/lib/cdnca-control/downloads', DATA_DIR: '/var/lib/cdnca-control',
    SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID: '',
    SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION: '', SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY: '', ...env } })
}

const pin = { SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID: 'offline-root-v1', SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION: '1',
  SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY: 'A'.repeat(43) }

test('a complete offline-root pin enables the signer revocation consumer', () => {
  const result = render(pin)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, ['SIGNER_REVOCATION_CONSUMER_ENABLED=true',
    'SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_KEY_ID=offline-root-v1',
    'SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_GENERATION=1',
    `SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_PUBLIC_KEY_BASE64=${'A'.repeat(43)}`,
    'EDGE_SIGNER_TRUST_ENABLED=true',
    'EDGE_SIGNER_TRUST_DOWNLOADS_DIR=/var/lib/cdnca-control/downloads/edge-agent', ''].join('\n'))
})

test('without a pin the consumer stays disabled with a visible warning and nothing on stdout but the switch', () => {
  const result = render({})
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'SIGNER_REVOCATION_CONSUMER_ENABLED=false\nEDGE_SIGNER_TRUST_ENABLED=false\n')
  assert.match(result.stderr, /签名密钥泄露吊销/)
})

test('partial or malformed pins and non-origin licensing servers fail the install instead of breaking startup later', () => {
  for (const env of [
    { ...pin, SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION: '' },
    { ...pin, SIGNER_REVOCATION_OFFLINE_ROOT_GENERATION: '0' },
    { ...pin, SIGNER_REVOCATION_OFFLINE_ROOT_PUBLIC_KEY: 'A'.repeat(44) },
    { ...pin, SIGNER_REVOCATION_OFFLINE_ROOT_KEY_ID: 'bad id' },
    { ...pin, LICENSING_SERVER: 'https://auth.example/path' },
  ]) {
    const result = render(env)
    assert.notEqual(result.status, 0, JSON.stringify(env))
    assert.equal(result.stdout, '')
  }
})

test('the control environment appends the signer revocation block and the help documents the options', () => {
  assert.match(block('write_environment'), /\n {2}signer_revocation_environment >>"\$\{CONFIG_DIR\}\/control\.env"\n(?: {2}! remote_gateway_access \|\| gateway_access_environment >>"\$\{CONFIG_DIR\}\/control\.env"\n)?(?: {2}local_gateway_environment >>"\$\{CONFIG_DIR\}\/control\.env"\n)? {2}chmod 0600/)
  for (const option of ['key-id', 'generation', 'public-key']) {
    assert.match(block('usage'), new RegExp(`--signer-revocation-offline-root-${option}`))
    assert.match(block('parse_args'), new RegExp(`--signer-revocation-offline-root-${option}\\)`))
  }
})
