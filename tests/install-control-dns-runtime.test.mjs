import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
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
// Every other ${NAME} in the env template is bound to a placeholder so `set -u` passes.
const placeholders = [...new Set([...block('write_environment').matchAll(/\$\{([A-Z_0-9]+)\}/g)].map((match) => match[1]))]
  .filter((name) => !/^(DNS_RECONCILE|CNAME_ALLOCATION)_/.test(name) && !name.endsWith('_BASE64') &&
    !['ACCESS_TOKEN_SECRET', 'CONFIG_DIR'].includes(name))
  .map((name) => `${name}=placeholder`)

function renderEnvironment() {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-dns-runtime-'))
  try {
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }', ...placeholders,
      'CNAME_ALLOCATION_HMAC_KEY_BASE64=""', block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'),
      'generate_runtime_secrets', 'write_environment'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory, KEY_DIR: join(directory, 'keys'),
        PKI_DIR: join(directory, 'pki'), UPGRADE_KEY_DIR: join(directory, 'upgrade') },
    })
    assert.equal(result.status, 0, result.stderr)
    const path = join(directory, 'control.env')
    assert.equal(statSync(path).mode & 0o777, 0o600)
    return Object.fromEntries(readFileSync(path, 'utf8').trim().split('\n').map((line) => {
      const index = line.indexOf('=')
      return [line.slice(0, index), line.slice(index + 1)]
    }))
  } finally { rmSync(directory, { recursive: true }) }
}

test('fresh install enables the DNS write runtime without a workload mTLS listener', () => {
  const environment = renderEnvironment()
  assert.equal(environment.DNS_RECONCILE_ENABLED, 'true')
  assert.equal(environment.DNS_RECONCILE_WORKLOAD_MTLS_ENABLED, 'false')
  for (const name of Object.keys(environment)) {
    assert.ok(!name.startsWith('DNS_RECONCILE_WORKLOAD_MTLS_') || name === 'DNS_RECONCILE_WORKLOAD_MTLS_ENABLED', name)
    assert.ok(!['DNS_RECONCILE_RESOLVER_ENDPOINTS', 'DNS_RECONCILE_WORKLOAD_IDENTITIES'].includes(name), name)
  }
  const publicResolvers = environment.DNS_RECONCILE_PROPAGATION_PUBLIC_RESOLVERS.split(',')
  assert.deepEqual(publicResolvers.map((entry) => entry.split('=')[1]), ['1.1.1.1:53', '8.8.8.8:53', '223.5.5.5:53'])
  assert.equal(Number(environment.DNS_RECONCILE_PROPAGATION_PUBLIC_QUORUM), publicResolvers.length - 1,
    'public quorum must tolerate exactly one failed resolver')
  assert.ok(environment.DNS_RECONCILE_PROPAGATION_BOOTSTRAP_RESOLVERS.split(',').length >= 2)
})

test('fresh install generates a distinct 32-byte CNAME allocation key per installation', () => {
  const first = renderEnvironment()
  const second = renderEnvironment()
  assert.equal(first.CNAME_ALLOCATION_HMAC_KEY_ID, 'cname-allocation-v1')
  assert.equal(Buffer.from(first.CNAME_ALLOCATION_HMAC_KEY, 'base64').length, 32)
  assert.notEqual(first.CNAME_ALLOCATION_HMAC_KEY, second.CNAME_ALLOCATION_HMAC_KEY)
  assert.notEqual(first.CNAME_ALLOCATION_HMAC_KEY, first.DNS_CREDENTIAL_KEY_BASE64)
})

test('write_environment refuses to run without a generated CNAME allocation key', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-dns-runtime-'))
  try {
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }', ...placeholders,
      block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'), 'generate_runtime_secrets',
      'CNAME_ALLOCATION_HMAC_KEY_BASE64=""', 'write_environment'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory },
    })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /runtime secrets were not generated/)
  } finally { rmSync(directory, { recursive: true }) }
})
