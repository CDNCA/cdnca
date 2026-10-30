import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const directory = dirname(fileURLToPath(import.meta.url))
const root = resolve(directory, '../..')
const contract = JSON.parse(await readFile(join(directory, 'contract.json'), 'utf8'))

assert.equal(contract.schema_version, 1)
assert.deepEqual(contract.command_stream.subjects, ['cdnca.agent.commands.cache.*'])
assert.deepEqual(contract.status_stream.subjects, [
  'cdnca.agent.deployment-status.cache.*',
  'cdnca.agent.deployment-status.cache-dlq.*',
])
assert.equal(contract.command_stream.replicas, 3)
assert.equal(contract.status_stream.replicas, 3)
assert.equal(contract.consumer.ack_policy, 'explicit')
assert.equal(contract.consumer.max_request_batch, 1)

const sources = new Map()
for (const relative of [
  'services/control-api/internal/cachecontrolruntime/config.go',
  'services/control-api/internal/cachecontrolruntime/runtime.go',
  'services/control-api/internal/cachecontrolruntime/nats.go',
  'services/control-api/internal/cachecontrolruntime/processor.go',
  'services/control-api/internal/cachecontrol/lifecycle.go',
  'agents/edge-agent/internal/cachetask/carrier.go',
  'agents/edge-agent/internal/cachetask/manager.go',
  'agents/edge-agent/internal/cachetask/prewarm.go',
  'agents/edge-agent/internal/gatewayclient/cache_control_store.go',
]) {
  sources.set(relative, await readFile(join(root, relative), 'utf8'))
}

const requireTokens = (file, tokens) => {
  const source = sources.get(file)
  for (const token of tokens) {
    assert.ok(source.includes(token), `${file} missing ${JSON.stringify(token)}`)
  }
}

requireTokens('services/control-api/internal/cachecontrolruntime/config.go', [
  'TenantDispatchRate', 'SiteDispatchRate', 'NodeDispatchRate',
])
requireTokens('services/control-api/internal/cachecontrolruntime/runtime.go', [
  'OpenClaims(', 'newDispatchLimiter(', '.limiter.Wait(', 'Claim(',
])
assert.ok(
  sources.get('services/control-api/internal/cachecontrolruntime/runtime.go').indexOf('OpenClaims(') <
    sources.get('services/control-api/internal/cachecontrolruntime/runtime.go').indexOf('Claim('),
  'open claim recovery must precede fresh claims',
)
requireTokens('services/control-api/internal/cachecontrolruntime/nats.go', [
  'nats.MsgIdHdr', 'PublishDLQ(', 'MaxDeliver:', 'AckExplicitPolicy',
])
requireTokens('services/control-api/internal/cachecontrolruntime/processor.go', [
  'cachecontrol.ErrReportConflict', 'runtime.control.Report(', 'runtime.quarantine(',
])
requireTokens('services/control-api/internal/cachecontrol/lifecycle.go', [
  'jobstate.RetryTx(', 'jobstate.CancelTx(', 'jobstate.ReportTx(', 'leaseRetryBackoff(',
])
requireTokens('agents/edge-agent/internal/cachetask/carrier.go', [
  'type CarrierReceipt struct', 'ActiveConfigUnchanged', 'ConfigRevision', 'validateCarrierResult',
])
requireTokens('agents/edge-agent/internal/cachetask/manager.go', [
  'retryDelayWithServerHint(', 'siteLimiterIdentity(',
])
requireTokens('agents/edge-agent/internal/cachetask/prewarm.go', [
  'Retry-After', 'response.Header.Values',
])
requireTokens('agents/edge-agent/internal/gatewayclient/cache_control_store.go', [
  'CommandDigest', 'AckedThrough', 'cache control status sequence regressed',
])

console.log('CACHE_05_STATIC_CONTRACT_PASS')
