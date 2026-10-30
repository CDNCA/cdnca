// Fresh control installs turn on automatic edge publication (market leaf
// delivery depends on it) with a configuration the control-api loader accepts:
// services/control-api/cmd/control-api/edge_automatic_publication_runtime.go.
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const loader = readFileSync(new URL('../services/control-api/cmd/control-api/edge_automatic_publication_runtime.go', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function renderEnvironment() {
  const placeholders = [...new Set([...block('write_environment').matchAll(/\$\{([A-Z_0-9]+)\}/g)].map((match) => match[1]))]
    .filter((name) => !name.endsWith('_BASE64') && !['ACCESS_TOKEN_SECRET', 'CONFIG_DIR'].includes(name))
    .map((name) => `${name}=placeholder`)
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-autopublish-'))
  try {
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }', ...placeholders,
      'CNAME_ALLOCATION_HMAC_KEY_BASE64=""', block('generate_runtime_secrets'), block('signer_revocation_environment'), block('remote_gateway_access'), block('local_gateway_environment'), 'GATEWAY_HOST=gateway.example.test GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443', block('write_environment'),
      'generate_runtime_secrets', 'write_environment'].join('\n')], { encoding: 'utf8', env: { ...process.env, CONFIG_DIR: directory } })
    assert.equal(result.status, 0, result.stderr)
    return readFileSync(join(directory, 'control.env'), 'utf8').trim().split('\n').map((line) => {
      const index = line.indexOf('=')
      return [line.slice(0, index), line.slice(index + 1)]
    })
  } finally { rmSync(directory, { recursive: true }) }
}

const seconds = (value) => {
  const match = /^(\d+)(ms|s|m|h)$/.exec(value)
  assert.ok(match, `unsupported duration ${value}`)
  return Number(match[1]) * { ms: 0.001, s: 1, m: 60, h: 3600 }[match[2]]
}

test('control.env enables automatic publication with every key the loader requires', () => {
  const entries = renderEnvironment()
  const names = entries.map(([name]) => name)
  assert.equal(new Set(names).size, names.length, 'duplicate keys in control.env')
  const environment = Object.fromEntries(entries)
  // The loader accepts exactly these names under the prefix (unknown ones fail startup).
  const expected = [...loader.matchAll(/= "(EDGE_AUTOMATIC_PUBLICATION_[A-Z_]+)"/g)].map((match) => match[1]).sort()
  assert.equal(expected.length, 7)
  assert.deepEqual(names.filter((name) => name.startsWith('EDGE_AUTOMATIC_PUBLICATION_')).sort(), expected)
  assert.equal(environment.EDGE_AUTOMATIC_PUBLICATION_ENABLED, 'true')
  assert.match(environment.EDGE_AUTOMATIC_PUBLICATION_WORKER_ID, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/)
  const value = (name) => seconds(environment[`EDGE_AUTOMATIC_PUBLICATION_${name}`])
  // Bounds from loadEdgeAutomaticPublicationRuntimeConfigFromEnv.
  assert.ok(value('POLL_INTERVAL') >= 0.01 && value('POLL_INTERVAL') <= 60)
  assert.ok(value('ERROR_BACKOFF') >= 0.01 && value('ERROR_BACKOFF') <= 300)
  assert.ok(value('OPERATION_TIMEOUT') >= 0.1 && value('OPERATION_TIMEOUT') <= 300)
  assert.ok(value('LEASE_DURATION') >= 1 && value('LEASE_DURATION') <= 3600)
  assert.ok(value('RETRY_DELAY') >= 0 && value('RETRY_DELAY') <= 3600)
  assert.ok(value('LEASE_DURATION') > value('OPERATION_TIMEOUT'), 'lease must exceed the operation timeout')
  // ShutdownPeriod: 10s by default, 2 x analytics ingest operation timeout (10s) when
  // ANALYTICS_INGEST_ENABLED (runtime-extra.env sets it); stay within the smaller one.
  assert.ok(value('OPERATION_TIMEOUT') <= 10, 'operation timeout must not exceed the shutdown period')
})

test('automatic publication relies on the edge publication runtime enabled by runtime-extra.env', () => {
  const unit = block('setup_service')
  const order = ['control.env', 'runtime-extra.env'].map((name) => unit.indexOf(`EnvironmentFile=\${CONFIG_DIR}/${name}`))
  assert.ok(order[0] >= 0 && order[1] > order[0], 'runtime-extra.env must be loaded after control.env')
  const runtime = readFileSync(new URL('../scripts/native-runtime/configure-control-runtime.py', import.meta.url), 'utf8')
  assert.match(runtime, /"EDGE_PUBLISH_RUNTIME_ENABLED": "true"/)
  // The runtime configurator rejects EDGE_PUBLISH_* keys it does not own in control.env;
  // the automatic publication prefix must stay outside that list.
  assert.ok(!'EDGE_AUTOMATIC_PUBLICATION_ENABLED'.startsWith('EDGE_PUBLISH_'))
})
