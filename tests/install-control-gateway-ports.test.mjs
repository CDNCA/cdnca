// ADR 0013 §3.5 / GW-04: Gateway ports are random in 20000-29999 by default,
// may be chosen in 1024-65535, and bad choices fail with a suggested pair.
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
const reserved = source.match(/^readonly NATIVE_RESERVED_PORTS=.*$/m)[0]

function select({ ports = '', master = '443', busy = [] } = {}) {
  const script = ['set -Eeuo pipefail', block('fail'), reserved, block('gateway_port_listening'), block('gateway_port_usable'),
    block('gateway_port_suggestion'), block('select_gateway_ports'),
    // ss -H -ltn "sport = :N" -> the filter is the last argument.
    `ss() { local filter=\${!#} port; port=\${filter##*:}; case " ${busy.join(' ')} " in *" $port "*) printf 'LISTEN\\n' ;; esac; }`,
    `GATEWAY_PORTS=${JSON.stringify(ports)} MASTER_PORT=${master} GATEWAY_ENROLLMENT_PORT= GATEWAY_AGENT_PORT=`,
    'select_gateway_ports', 'first="$GATEWAY_ENROLLMENT_PORT,$GATEWAY_AGENT_PORT"', 'select_gateway_ports',
    'printf "%s|%s,%s" "$first" "$GATEWAY_ENROLLMENT_PORT" "$GATEWAY_AGENT_PORT"'].join('\n')
  return spawnSync('bash', ['-c', script], { encoding: 'utf8', timeout: 20000 })
}

test('default ports are two distinct free ports in 20000-29999 and stay stable on re-check', () => {
  for (let round = 0; round < 20; round += 1) {
    const result = select({ busy: ['20000', '20001'] })
    assert.equal(result.status, 0, result.stderr)
    const [first, second] = result.stdout.split('|')
    assert.equal(first, second, 'a second call must not re-roll the ports')
    const [enrollment, agent] = first.split(',').map(Number)
    assert.notEqual(enrollment, agent)
    for (const port of [enrollment, agent]) {
      assert.ok(port >= 20000 && port <= 29999, `${port} outside 20000-29999`)
      assert.ok(port !== 20000 && port !== 20001, 'busy port chosen')
    }
  }
})

test('explicit ports are accepted in 1024-65535', () => {
  const result = select({ ports: '21443,21444' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, '21443,21444|21443,21444')
  assert.equal(select({ ports: '19443,19444' }).status, 0)
})

test('invalid explicit ports fail with a suggested free pair', () => {
  for (const [ports, master, busy, reason] of [
    ['80,19444', '443', [], /between 1024 and 65535/],
    ['70000,19444', '443', [], /between 1024 and 65535/],
    ['443,19444', '443', [], /between 1024 and 65535/],
    ['8443,19444', '8443', [], /equals the management HTTPS port/],
    ['21443,21443', '443', [], /must differ/],
    ['21443,21444', '443', ['21444'], /already in use/],
    ['4222,21444', '443', [], /reserved by a native runtime service/],
    ['21443', '443', [], /must be <enrollment>,<agent>/],
  ]) {
    const result = select({ ports, master, busy: [...busy, '20000'] })
    assert.notEqual(result.status, 0, `${ports} accepted`)
    assert.match(result.stderr, reason, ports)
    if (!/must be <enrollment>/.test(reason.source)) assert.match(result.stderr, /--gateway-ports 20002,20003/, ports)
  }
})

test('selected ports flow into preflight, firewall hints, Gateway env and the completion notice', () => {
  const preflight = block('run_preflight')
  assert.match(preflight, /select_gateway_ports/)
  assert.match(preflight, /control_preflight_ports/)
  assert.match(block('control_preflight_ports'), /"\$GATEWAY_ENROLLMENT_PORT:节点注册" "\$GATEWAY_AGENT_PORT:节点通道"/)
  assert.match(preflight, /preflight_check_firewall "\$port" "\$GATEWAY_ENROLLMENT_PORT" "\$GATEWAY_AGENT_PORT"/)
  assert.doesNotMatch(preflight, /1944[34]/)
  const env = block('write_gateway_environment')
  assert.match(env, /CDNCA_GATEWAY_ENROLLMENT_ADDR=0\.0\.0\.0:\$\{GATEWAY_ENROLLMENT_PORT\}/)
  assert.match(env, /CDNCA_GATEWAY_AGENT_ADDR=0\.0\.0\.0:\$\{GATEWAY_AGENT_PORT\}/)
  const notice = spawnSync('bash', ['-c', [block('print_gateway_ports'), 'GATEWAY_ENROLLMENT_PORT=23001 GATEWAY_AGENT_PORT=23002 print_gateway_ports'].join('\n')], { encoding: 'utf8' })
  assert.match(notice.stderr, /注册 23001，通道 23002/)
  assert.match(notice.stderr, /回源端口填 23001/)
  const main = block('main')
  assert.ok(main.indexOf('print_gateway_ports') > main.indexOf('configure_firewall'))
  assert.ok(main.indexOf('print_gateway_ports') < main.indexOf("log 'cdnca community edition installed and ready'"))
  assert.match(block('parse_args'), /--gateway-ports\) need_value "\$@"; GATEWAY_PORTS=\$2/)
})

const nodeSource = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
function nodeBlock(name) {
  const lines = nodeSource.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

test('node installer turns gateway_endpoints into gateway.endpoints and rejects bad entries', () => {
  const run = (endpoints) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', 'fail() { printf "%s\\n" "$*" >&2; exit 1; }',
    nodeBlock('gateway_endpoints_json'), `GATEWAY_ENDPOINTS=${JSON.stringify(endpoints)}`, 'gateway_endpoints_json'].join('\n')], { encoding: 'utf8' })
  const ok = run('gw.example.com:443|gateway.internal|ws|gw.example.com 203.0.113.10:21444|gateway.internal')
  assert.equal(ok.status, 0, ok.stderr)
  assert.deepEqual(JSON.parse(ok.stdout), [
    { address: 'gw.example.com:443', server_name: 'gateway.internal', transport: 'ws', tunnel_host: 'gw.example.com' },
    { address: '203.0.113.10:21444', server_name: 'gateway.internal', transport: 'grpc' },
  ])
  assert.deepEqual(JSON.parse(run('').stdout), [])
  assert.notEqual(run('gw.example.com|gateway.internal').status, 0)
  assert.notEqual(run('gw.example.com:443|gateway.internal|quic').status, 0)
  assert.match(nodeBlock('write_config'), /--argjson endpoints "\$\(gateway_endpoints_json\)"/)
})
