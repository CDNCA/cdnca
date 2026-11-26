// --release-server：官网与 README 给的是发布目录本身（https://www.cdnca.com/downloads/ce，其下直接是
// control-native/、edge-agent/）；只写域名时沿用发布包 downloads/ 目录布局（自建镜像、测试发布站）。
// 主控整包、校验和、信任文件、节点包预取与运行时归档回退都按同一规则拼，不再多拼一层 downloads/。
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

const urlNames = ['CONTROL_NATIVE_URL', 'CONTROL_NATIVE_FALLBACK_URL', 'CONTROL_NATIVE_SHA256_URL', 'CONTROL_NATIVE_SHA256_FALLBACK_URL',
  'CONTROL_NATIVE_TRUST_URL', 'CONTROL_NATIVE_TRUST_FALLBACK_URL', 'EDGE_AGENT_URL', 'EDGE_AGENT_FALLBACK_URL', 'EDGE_AGENT_SHA256_URL',
  'EDGE_AGENT_SHA256_FALLBACK_URL', 'EDGE_ARTIFACT_TRUST_URL', 'EDGE_ARTIFACT_TRUST_FALLBACK_URL', 'RUNTIME_ARCHIVE_URL', 'RUNTIME_ARCHIVE_FALLBACK_URL']

// normalise_defaults 里拼下载地址的那一段，配上 release_artifact_base 单独执行。
function urls(server) {
  const lines = block('normalise_defaults').split('\n')
  const from = lines.findIndex((line) => line.includes('release_base=$(release_artifact_base'))
  const to = lines.findIndex((line) => line.includes('RUNTIME_ARCHIVE_FALLBACK_URL=${RUNTIME_ARCHIVE_FALLBACK_URL'))
  assert.ok(from > 0 && to > from, 'normalise_defaults lost its release URL block')
  const print = urlNames.map((name) => `printf '%s=%s\\n' ${name} "\${${name}}"`)
  const script = ['set -Eeuo pipefail', block('release_artifact_base'), `LICENSING_SERVER=${server}`, `LICENSING_SERVER_FALLBACK=${server}`,
    'f() {', 'local release_base release_fallback_base', ...lines.slice(from, to + 1), ...print, '}', 'f']
  const result = spawnSync('bash', ['-c', script.join('\n')], { encoding: 'utf8', timeout: 20000 })
  assert.equal(result.status, 0, result.stderr)
  return Object.fromEntries(result.stdout.trim().split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2)))
}

test('the official release directory is used as is (no extra downloads/ level)', () => {
  const got = urls('https://www.cdnca.com/downloads/ce')
  assert.equal(got.CONTROL_NATIVE_URL, 'https://www.cdnca.com/downloads/ce/control-native/latest/cdnca-control-native.tar')
  assert.equal(got.CONTROL_NATIVE_SHA256_URL, 'https://www.cdnca.com/downloads/ce/control-native/latest/SHA256SUMS')
  assert.equal(got.CONTROL_NATIVE_TRUST_URL, 'https://www.cdnca.com/downloads/ce/control-native/artifacts.json')
  assert.equal(got.EDGE_AGENT_URL, 'https://www.cdnca.com/downloads/ce/edge-agent/latest/cdnca-edge-agent.tar.gz')
  assert.equal(got.EDGE_AGENT_SHA256_URL, 'https://www.cdnca.com/downloads/ce/edge-agent/latest/SHA256SUMS')
  assert.equal(got.EDGE_ARTIFACT_TRUST_URL, 'https://www.cdnca.com/downloads/ce/edge-agent/artifacts.json')
  assert.equal(got.RUNTIME_ARCHIVE_URL, 'https://www.cdnca.com/downloads/ce/control-native/runtime')
  for (const name of urlNames) assert.ok(!got[name].includes('/downloads/ce/downloads/'), `${name}=${got[name]}`)
})

test('a trailing slash and a bare origin keep working', () => {
  assert.equal(urls('https://www.cdnca.com/downloads/ce/').EDGE_AGENT_URL, 'https://www.cdnca.com/downloads/ce/edge-agent/latest/cdnca-edge-agent.tar.gz')
  const origin = urls('https://release.cdnca.smoke')
  assert.equal(origin.CONTROL_NATIVE_URL, 'https://release.cdnca.smoke/downloads/control-native/latest/cdnca-control-native.tar')
  assert.equal(origin.EDGE_ARTIFACT_TRUST_FALLBACK_URL, 'https://release.cdnca.smoke/downloads/edge-agent/artifacts.json')
  assert.equal(origin.RUNTIME_ARCHIVE_FALLBACK_URL, 'https://release.cdnca.smoke/downloads/control-native/runtime')
})

test('no download URL is built from the release server plus downloads/ directly', () => {
  assert.doesNotMatch(block('normalise_defaults'), /\$LICENSING_SERVER(_FALLBACK)?\/downloads\//)
})
