// 主控几乎都套 CDN，CDN 不转发网关随机端口 20000–29999，
// 所以 tcp 传输下网关默认用本机公网 IP 直连；显式 --gateway-host 优先，取不到 IP 回落主控地址并警告；
// ws 传输仍走主控域名（经 CDN 443）。网关证书 SAN 同时含 IP 与主控域名；安装结尾与 check 提示放行两端口。
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  if (lines[start].endsWith('}')) return lines[start]
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

const deps = ['fail', 'warn', 'valid_host', 'valid_port', 'control_domain_is_ip', 'summary_host_addresses', 'gateway_transport_resolve',
  'default_gateway_host', 'prompt_public_endpoints']
// curl 桩：IPIFY 为空时模拟探测失败；ip 桩：只给内网地址（云主机 NAT 后的常见情形）。
function resolve(env = {}, { lang = 'zh' } = {}) {
  return spawnSync('bash', ['-c', ['set -Eeuo pipefail', ...deps.map(block),
    `curl() { [ -n "\${IPIFY:-}" ] || return 7; printf '%s' "$IPIFY"; }`,
    `ip() { printf '%s\\n' '2: eth0    inet 10.0.0.5/8 scope global eth0'; }`,
    `INSTALL_LANG=${lang}`,
    'prompt_public_endpoints',
    'printf "%s\\n" "$GATEWAY_HOST"'].join('\n')], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, MASTER_HOST: 'Control.Example.com', MASTER_PORT: '443', GATEWAY_HOST: '', CONTROL_DOMAIN: '',
      PUBLIC_CERT_FILE: '', GATEWAY_TRANSPORT: '', GATEWAY_TUNNEL_HOST: '', ORIGIN_AUTH: 'false', REAL_IP_HEADER_SET: 'false', ...env },
  })
}

test('domain console defaults the Gateway host to the public IP', () => {
  const result = resolve({ IPIFY: '198.51.100.20' })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout.trim(), '198.51.100.20')
  assert.equal(result.stderr, '')
})

test('explicit --gateway-host wins and an IP console host is kept', () => {
  assert.equal(resolve({ IPIFY: '198.51.100.20', GATEWAY_HOST: 'GW.example.com' }).stdout.trim(), 'gw.example.com')
  assert.equal(resolve({ IPIFY: '198.51.100.20', MASTER_HOST: '203.0.113.9' }).stdout.trim(), '203.0.113.9')
})

test('without a public IP the Gateway falls back to the console host with a warning', () => {
  for (const ipify of ['', '<html>blocked</html>']) {
    const result = resolve({ IPIFY: ipify })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.trim(), 'control.example.com')
    assert.match(result.stderr, /未取到本机公网 IP.*--gateway-host/)
  }
  assert.match(resolve({ IPIFY: '' }, { lang: 'en' }).stderr, /public IP.*--gateway-host/)
})

test('ws transport keeps the console domain (nodes go through the CDN on 443)', () => {
  assert.equal(resolve({ IPIFY: '198.51.100.20', GATEWAY_TRANSPORT: 'ws' }).stdout.trim(), 'control.example.com')
  assert.equal(resolve({ IPIFY: '198.51.100.20', ORIGIN_AUTH: 'true' }).stdout.trim(), 'control.example.com')
})

test('normalise_defaults no longer copies the console host into the Gateway host', () => {
  assert.doesNotMatch(source, /GATEWAY_HOST=\$\{GATEWAY_HOST:-\$MASTER_HOST\}/)
})

test('Gateway certificate names the IP and the console domain once', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-gw-san-'))
  try {
    const run = (gateway, master) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('host_san'), block('gateway_server_san'),
      `GATEWAY_HOST=${gateway} MASTER_HOST=${master}`, 'gateway_server_san'].join('\n')], { encoding: 'utf8' })
    assert.equal(run('198.51.100.20', 'control.example.com').stdout, 'IP:198.51.100.20,DNS:control.example.com,DNS:localhost,IP:127.0.0.1')
    assert.equal(run('control.example.com', 'control.example.com').stdout, 'DNS:control.example.com,DNS:localhost,IP:127.0.0.1')
    assert.match(block('generate_pki'), /issue_certificate gateway-server "\$GATEWAY_HOST" "\$\(gateway_server_san\)"/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('install summary tells the user to open both Gateway ports for direct node connections', () => {
  const run = (lang) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('gateway_direct_ports_hint'),
    `INSTALL_LANG=${lang}`, 'gateway_direct_ports_hint 198.51.100.20 21443 21444'].join('\n')], { encoding: 'utf8' })
  assert.equal(run('zh').stdout, '请在防火墙/云安全组放行网关两个端口 21443、21444（TCP），节点直连 198.51.100.20')
  assert.equal(run('en').stdout, 'Open both Gateway ports 21443 and 21444 (TCP) in the firewall / cloud security group; nodes connect directly to 198.51.100.20')
  // 摘要只在 tcp 传输打印；check 从 node-install-defaults 取地址，非 ws 时打印。
  assert.match(block('control_install_summary'),
    /\[ "\$\{GATEWAY_TRANSPORT:-tcp\}" = ws \] \|\| printf .*gateway_direct_ports_hint "\$GATEWAY_HOST" "\$GATEWAY_ENROLLMENT_PORT" "\$GATEWAY_AGENT_PORT"/)
  assert.match(block('check_main'), /gateway_direct_ports_hint/)
})
