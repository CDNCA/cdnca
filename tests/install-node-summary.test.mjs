// installer-i18n A：节点安装完成简版摘要（节点 ID、主控、网关与传输、放行端口、健康检查、日志），不含令牌。
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
const i18n = readFileSync(new URL('../scripts/lib/install-i18n.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function run(lang, transport = 'grpc') {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-node-summary-'))
  writeFileSync(join(dir, 'identity.json'), JSON.stringify({ version: 1, node_id: '9b1c0f9e-0000-4000-8000-000000000001' }))
  const script = ['set -Eeuo pipefail', i18n, block('node_install_summary'), `install_lang_init --lang ${lang}`,
    `INSTALLER_COPY=/var/lib/cdnca-node-install/install-node.sh IDENTITY_DIR=${JSON.stringify(dir)} SERVICE_NAME=cdnca-edge-agent NODE_NAME=edge-1 CONTROL_PLANE=https://cdnca.com`,
    `GATEWAY_ADDRESS=gateway.cdnca.com:21444 GATEWAY_TRANSPORT=${transport} GATEWAY_TUNNEL_HOST=${transport === 'ws' ? 'gw-cdn.cdnca.com' : ''}`,
    `ENROLLMENT_TOKEN=tok_secret_1 REGISTRATION_KEY=key_secret_2 PROGRESS_LOG=/var/log/cdnca-install-node-x.log`,
    'node_install_summary'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH } })
  rmSync(dir, { recursive: true, force: true })
  return result
}

test('Chinese node summary lists node, control plane, Gateway, ports, health check and logs', () => {
  const result = run('zh')
  assert.equal(result.status, 0, result.stderr)
  for (const expected of ['CDNCA 节点安装完成', '节点 ID： 9b1c0f9e-0000-4000-8000-000000000001', '节点名称： edge-1',
    '所属主控： https://cdnca.com', '网关地址： gateway.cdnca.com:21444  传输方式： grpc', 'TCP 80, TCP 443', 'UDP 443',
    'http://127.0.0.1:18080/healthz', 'journalctl -u cdnca-edge-agent', '/usr/libexec/cdnca-edge-agent/uninstall.sh', '核对： /var/lib/cdnca-node-install/install-node.sh check']) {
    assert.ok(result.stderr.includes(expected), `missing ${expected}\n${result.stderr}`)
  }
  assert.doesNotMatch(result.stderr, /tok_secret_1|key_secret_2/)
})

test('English node summary is in English and shows the WebSocket tunnel', () => {
  const result = run('en', 'ws')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /CDNCA node installed/)
  assert.match(result.stderr, /transport: ws \(WebSocket tunnel, gw-cdn\.cdnca\.com\)/)
  assert.doesNotMatch(result.stderr, /\p{Script=Han}/u)
})

test('node main prints the summary last', () => {
  assert.match(block('main'), /node_install_summary\n  node_next_steps\n  progress_done\n}$/)
})
