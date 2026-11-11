import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'

// 例：ws 主控，node-install-defaults 的首选入口是 ws（带 gateway_tunnel_host）。
// 重装时命令行显式 --gateway-transport grpc，安装器把主控的 tunnel host 填进来后在 normalise_defaults 拒绝：
// 「--gateway-tunnel-host requires --gateway-transport ws」。命令行显式指定的传输与主控首选入口不同时，
// 主控首选入口的字段（地址、注册地址、server name、tunnel host）描述的是另一种传输，必须丢掉并说明。
const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')
const rootless = script.replace(`[ "$EUID" -eq 0 ] || fail 'run this installer as root'`, ':')
assert.notEqual(rootless, script)

const run = (body, command) => spawnSync('bash', ['-c', `
fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
cat >"$fake/curl" <<'CURL'
#!/usr/bin/env bash
printf '%s' "$DEFAULTS_BODY"
CURL
chmod +x "$fake/curl"; export PATH="$fake:$PATH"
${rootless}
${command}`], { encoding: 'utf8', env: { ...process.env, DEFAULTS_BODY: body, INSTALL_LANG: 'zh' } })

const pin = 'b'.repeat(64)
// 与 73 当时下发的形状一致：首选 ws 入口（经 443 隧道），grpc 直连入口在备用列表里。
const wsConsole = [`upgrade_trust_sha256=${pin}`, 'gateway_enrollment_address=gateway.cdnca.com:443',
  'gateway_address=gateway.cdnca.com:443', 'gateway_server_name=gateway.cdnca.com', 'gateway_transport=ws',
  'gateway_tunnel_host=gateway.cdnca.com', 'gateway_endpoints=gateway.cdnca.com:20407|gateway.cdnca.com|grpc',
  'download_fallback_origin=https://auth.example', ''].join('\n')
const grpcConsole = [`upgrade_trust_sha256=${pin}`, 'gateway_enrollment_address=gw.example:19443',
  'gateway_address=gw.example:19444', 'gateway_server_name=gw.example', ''].join('\n')
const show = `printf '%s|%s|%s|%s|%s|%s\\n' "$GATEWAY_TRANSPORT" "$GATEWAY_ENROLLMENT_ADDRESS" "$GATEWAY_ADDRESS" "$GATEWAY_SERVER_NAME" "$GATEWAY_TUNNEL_HOST" "$UPGRADE_TRUST_SHA256"`
const base = 'parse_args --control-plane https://console.cdnca.com --token fixture-once'

test('explicit grpc on a ws console with the reinstall flags no longer fails on the console tunnel host', () => {
  const result = run(wsConsole, `${base} --gateway-transport grpc --gateway-enrollment-address gateway.cdnca.com:29402 \\
  --gateway-address gateway.cdnca.com:20407 --gateway-server-name gateway.cdnca.com
load_console_defaults
normalise_defaults
${show}`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim().split('\n').at(-1),
    `grpc|gateway.cdnca.com:29402|gateway.cdnca.com:20407|gateway.cdnca.com||${pin}`)
  // 说明丢掉了哪个字段；命令行已给的三个地址字段没有被主控覆盖，不在丢弃列表里。
  assert.match(result.stderr, /主控默认入口是 ws，命令行指定 grpc，已忽略主控下发的 gateway_tunnel_host/)
  assert.doesNotMatch(result.stderr, /gateway_address|gateway_enrollment_address|gateway_server_name/)
})

test('explicit grpc alone drops every field of the ws primary entry instead of dialling grpc on the tunnel port', () => {
  const result = run(wsConsole, `${base} --gateway-transport grpc
load_console_defaults
normalise_defaults
${show}`)
  assert.equal(result.status, 0, result.stderr)
  // :443 是 ws 隧道端口；丢掉后回到安装器自身的 grpc 默认（控制台主机 + 默认网关端口）。
  assert.equal(result.stdout.trim().split('\n').at(-1), `grpc|console.cdnca.com:19443|console.cdnca.com:19444|console.cdnca.com||${pin}`)
  assert.match(result.stderr, /已忽略主控下发的 gateway_enrollment_address、gateway_address、gateway_server_name、gateway_tunnel_host/)
})

test('explicit ws on a grpc console drops the grpc primary entry', () => {
  const result = run(grpcConsole, `${base} --gateway-transport ws --gateway-address console.cdnca.com:443
load_console_defaults
normalise_defaults
${show}`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim().split('\n').at(-1), `ws|console.cdnca.com:19443|console.cdnca.com:443|console.cdnca.com||${pin}`)
  assert.match(result.stderr, /主控默认入口是 grpc，命令行指定 ws，已忽略主控下发的 gateway_enrollment_address、gateway_server_name/)
})

test('without an explicit transport, or with the same one, the console defaults are kept unchanged', () => {
  for (const flags of ['', '--gateway-transport ws']) {
    const result = run(wsConsole, `${base} ${flags}
load_console_defaults
normalise_defaults
${show}`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim().split('\n').at(-1),
      `ws|gateway.cdnca.com:443|gateway.cdnca.com:443|gateway.cdnca.com|gateway.cdnca.com|${pin}`)
    assert.doesNotMatch(result.stderr, /已忽略主控下发/)
  }
  const grpc = run(grpcConsole, `${base} --gateway-transport grpc
load_console_defaults
normalise_defaults
${show}`)
  assert.equal(grpc.status, 0, grpc.stderr)
  assert.equal(grpc.stdout.trim().split('\n').at(-1), `grpc|gw.example:19443|gw.example:19444|gw.example||${pin}`)
})

test('a tunnel host passed on the command line with grpc is still refused', () => {
  const result = run(wsConsole, `${base} --gateway-transport grpc --gateway-tunnel-host gateway.cdnca.com
load_console_defaults
normalise_defaults`)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /--gateway-tunnel-host requires --gateway-transport ws/)
})

// Ws 主控「重装此节点」命令带发布列表第一个 grpc 入口。套 CDN、直连端口不通的节点仍有
// 443 WebSocket 回退：注册（--gateway-fallback-tunnel-address）和长连接（gateway.endpoints 末尾的 ws 条目）都经主控 443。
test('the reinstall command of a ws console keeps the 443 WebSocket fallback for a node behind a CDN', () => {
  const result = run(wsConsole, `${base} --gateway-enrollment-address gateway.cdnca.com:29402 \\
  --gateway-address gateway.cdnca.com:20407 --gateway-server-name gateway.cdnca.com --gateway-transport grpc
load_console_defaults
normalise_defaults
printf '%s|%s\\n' "$GATEWAY_FALLBACK_TUNNEL_ADDRESS" "$GATEWAY_ENDPOINTS"`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim().split('\n').at(-1),
    'console.cdnca.com:443|gateway.cdnca.com:20407|gateway.cdnca.com|grpc console.cdnca.com:443|gateway.cdnca.com|ws')
})
