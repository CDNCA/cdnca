import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

// 直连优先，直连不通自动换管理端 443 的 WebSocket，都不行再报错且写清楚。
const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')

const run = (command, lang = 'zh') => spawnSync('bash', ['-c', `${script}\n${command}`], {
  encoding: 'utf8', env: { ...process.env, INSTALL_LANG: lang },
})

test('direct grpc install falls back to the management HTTPS WebSocket for enrollment and the session', () => {
  const result = run(`CONTROL_PLANE=https://diaocdn.com GATEWAY_TRANSPORT=grpc GATEWAY_SERVER_NAME=203.0.113.5 GATEWAY_ENDPOINTS=''
gateway_fallback_defaults
printf '%s|%s\\n' "$GATEWAY_FALLBACK_TUNNEL_ADDRESS" "$GATEWAY_ENDPOINTS"
CONTROL_PLANE=https://[2001:db8::1]:8443 GATEWAY_ENDPOINTS='gw-b:21444|gw-b|grpc'
gateway_fallback_defaults
printf '%s|%s\\n' "$GATEWAY_FALLBACK_TUNNEL_ADDRESS" "$GATEWAY_ENDPOINTS"
CONTROL_PLANE=https://diaocdn.com GATEWAY_TRANSPORT=ws GATEWAY_ENDPOINTS='' GATEWAY_FALLBACK_TUNNEL_ADDRESS=''
gateway_fallback_defaults
printf '%s|%s\\n' "$GATEWAY_FALLBACK_TUNNEL_ADDRESS" "$GATEWAY_ENDPOINTS"`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'diaocdn.com:443|diaocdn.com:443|203.0.113.5|ws\n' +
    '[2001:db8::1]:8443|gw-b:21444|gw-b|grpc [2001:db8::1]:8443|203.0.113.5|ws\n|\n')
})

test('enrollment failure names the gateway, both attempts and the ports to open', () => {
  const log = JSON.stringify({ level: 'ERROR', msg: 'edge agent enrollment failed', event: 'enrollment_failed',
    error: 'gateway enrollment failed: connect to enrollment endpoint (...)',
    direct_address: 'diaocdn.com:26080', direct_error: 'context deadline exceeded',
    tunnel_address: 'diaocdn.com:443', tunnel_error: 'gateway tunnel upgrade 502 Bad Gateway: websocket: bad handshake' })
  const command = (lang) => run(`GATEWAY_ENROLLMENT_ADDRESS=diaocdn.com:26080 GATEWAY_ADDRESS=diaocdn.com:26081
log=$(mktemp); printf '%s\\n' '${log}' >"$log"; enrollment_failure_message "$log"; rm -f "$log"`, lang)
  const zh = command('zh')
  assert.equal(zh.status, 0, zh.stderr)
  assert.equal(zh.stdout, '无法连接网关 diaocdn.com:26080（直连 26080 超时；已尝试经 443 WebSocket：gateway tunnel upgrade 502 Bad Gateway: websocket: bad handshake）。请在主控防火墙/云安全组放行网关端口 26080、26081（TCP），或检查网关地址是否为主控 IP')
  const en = command('en')
  assert.equal(en.stdout, 'cannot connect to Gateway diaocdn.com:26080 (direct port 26080 timed out; tried WebSocket via 443: gateway tunnel upgrade 502 Bad Gateway: websocket: bad handshake). Open Gateway ports 26080, 26081 (TCP) in the control-plane firewall / cloud security group, or check that the Gateway address is the control-plane IP')
  assert.equal(en.stdout.includes('connect to enrollment endpoint'), false)
})

test('a refused direct dial without a tunnel attempt says so', () => {
  const log = JSON.stringify({ event: 'enrollment_failed', error: 'x', direct_address: '203.0.113.5:26080', direct_error: 'connection error: desc = "transport: Error while dialing: dial tcp 203.0.113.5:26080: connect: connection refused"' })
  const result = run(`GATEWAY_ENROLLMENT_ADDRESS=203.0.113.5:26080 GATEWAY_ADDRESS=203.0.113.5:26081
log=$(mktemp); printf '%s\\n' '${log}' >"$log"; enrollment_failure_message "$log"; rm -f "$log"`)
  assert.equal(result.stdout, '无法连接网关 203.0.113.5:26080（直连 26080 拒绝；未尝试 443 WebSocket）。请在主控防火墙/云安全组放行网关端口 26080、26081（TCP），或检查网关地址是否为主控 IP')
})

test('enroll passes the fallback tunnel address to the agent', () => {
  assert.match(script, /--gateway-fallback-tunnel-address "\$GATEWAY_FALLBACK_TUNNEL_ADDRESS"/)
})
