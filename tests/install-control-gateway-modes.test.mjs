// ADR 0013 §3.1/§3.3, GW-09/GW-10: install-control.sh --mode all|control|gateway.
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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
const constants = source.split('\n').filter((line) => /^readonly (CONTROL_INTERNAL_REMOTE_PORT|NATS_GATEWAY_WS_PORT|REDIS_GATEWAY_TLS_PORT)=/.test(line)).join('\n')
const bash = (script) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('warn'), constants, script].join('\n')], { encoding: 'utf8', timeout: 20000 })

test('all mode keeps loopback NATS, Redis and the ControlInternal certificate unchanged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gwmodes-'))
  try {
    const result = bash([block('remote_gateway_access'), block('nats_gateway_permissions'), block('write_nats_config'), block('host_san'),
      block('control_internal_server_san'), block('gateway_access_environment'), block('generate_gateway_access_secrets'),
      `INSTALL_MODE=all CONFIG_DIR=${dir} NATS_DATA_DIR=/data PKI_DIR=/pki CONTROL_DOMAIN=control.example.com REDIS_URL=redis://127.0.0.1:6379/0 REDIS_PORT=6379`,
      'generate_gateway_access_secrets; write_nats_config', 'printf "%s|%s|%s" "$(control_internal_server_san)" "$(gateway_access_environment)" "$REDIS_URL"'].join('\n'))
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, 'DNS:localhost,IP:127.0.0.1||redis://127.0.0.1:6379/0')
    assert.deepEqual(JSON.parse(readFileSync(join(dir, 'nats.json'), 'utf8')),
      { host: '127.0.0.1', port: 4222, http: '127.0.0.1:8222', max_payload: 4194304, jetstream: { store_dir: '/data' } })
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('control mode opens TLS listeners with a shared, restricted Gateway account', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gwmodes-'))
  try {
    const result = bash([block('remote_gateway_access'), block('nats_gateway_permissions'), block('write_nats_config'), block('host_san'),
      block('control_internal_server_san'), block('gateway_access_environment'), block('generate_gateway_access_secrets'),
      `INSTALL_MODE=control CONFIG_DIR=${dir} NATS_DATA_DIR=/data PKI_DIR=/pki CONTROL_DOMAIN=control.example.com GATEWAY_ACCESS_FILE=/var/lib/cdnca-control/gateway-access/allowed-ips REDIS_PORT=6379`,
      'generate_gateway_access_secrets; write_nats_config', 'printf "%s\\n%s\\n" "$(control_internal_server_san)" "$REDIS_URL"; gateway_access_environment'].join('\n'))
    assert.equal(result.status, 0, result.stderr)
    const lines = result.stdout.trim().split('\n')
    assert.equal(lines[0], 'DNS:localhost,IP:127.0.0.1,DNS:control.example.com')
    assert.match(lines[1], /^redis:\/\/:[0-9a-f]{48}@127\.0\.0\.1:6379\/0$/)
    const env = Object.fromEntries(lines.slice(2).map((line) => line.split(/=(.*)/s).slice(0, 2)))
    assert.equal(env.CDNCA_CONTROL_INTERNAL_REMOTE_ADDR, '0.0.0.0:9446')
    assert.equal(env.CDNCA_GATEWAY_ACCESS_FILE, '/var/lib/cdnca-control/gateway-access/allowed-ips')
    assert.equal(env.CDNCA_GATEWAY_REMOTE_CONTROL_ADDRESS, 'control.example.com:9446')
    assert.equal(env.CDNCA_GATEWAY_REMOTE_CONTROL_SERVER_NAME, 'control.example.com')
    assert.match(env.CDNCA_GATEWAY_REMOTE_REDIS_URL, /^rediss:\/\/cdnca-gateway:[0-9a-f]{48}@control\.example\.com:6380\/0$/)
    assert.match(env.CDNCA_GATEWAY_REMOTE_NATS_URL, /^wss:\/\/cdnca-gateway:[0-9a-f]{48}@control\.example\.com:4223$/)
    assert.equal(env.CDNCA_GATEWAY_REMOTE_TELEMETRY_NATS_URL, 'wss://control.example.com:4223')
    const nats = JSON.parse(readFileSync(join(dir, 'nats.json'), 'utf8'))
    assert.equal(nats.host, '127.0.0.1')
    assert.equal(nats.port, 4222)
    assert.equal(nats.no_auth_user, 'local')
    const [local, gateway] = nats.authorization.users
    assert.deepEqual([local.user, local.allowed_connection_types], ['local', ['STANDARD']])
    assert.deepEqual([gateway.user, gateway.allowed_connection_types], ['cdnca-gateway', ['WEBSOCKET']])
    assert.ok(env.CDNCA_GATEWAY_REMOTE_NATS_URL.includes(gateway.password))
    assert.ok(gateway.permissions.publish.deny.includes('$JS.API.STREAM.DELETE.>'))
    assert.deepEqual(nats.websocket.tls, { cert_file: '/pki/control-internal-server.pem', key_file: '/pki/control-internal-server-key.pem',
      ca_file: '/pki/gateway-client-ca-cert.pem', verify: true, min_version: '1.2' })
    assert.deepEqual([nats.websocket.host, nats.websocket.port], ['0.0.0.0', 4223])
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('all and control modes publish the co-located Gateway to nodes (K1)', () => {
  for (const [host, address, enrollment] of [['control.example.com', 'control.example.com:9444', 'control.example.com:9443'],
    ['2001:db8::1', '[2001:db8::1]:9444', '[2001:db8::1]:9443']]) {
    const result = bash([block('local_gateway_environment'), `GATEWAY_HOST=${host} GATEWAY_AGENT_PORT=9444 GATEWAY_ENROLLMENT_PORT=9443`,
      'local_gateway_environment'].join('\n'))
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, `CDNCA_GATEWAY_LOCAL_ADDRESS=${address}\nCDNCA_GATEWAY_LOCAL_SERVER_NAME=${host}\nCDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=${enrollment}\n`)
  }
  assert.match(block('write_environment'), /\n  local_gateway_environment >>"\$\{CONFIG_DIR\}\/control\.env"\n/)
})

test('Redis Gateway include requires client certificates and limits the ACL user to Gateway keys', () => {
  const body = block('configure_redis_gateway_access')
  assert.match(body, /tls-port \$\{REDIS_GATEWAY_TLS_PORT\}/)
  assert.match(body, /tls-auth-clients yes/)
  assert.match(body, /requirepass \$\{REDIS_DEFAULT_PASSWORD\}/)
  assert.match(body, /user cdnca-gateway on >\$\{REDIS_GATEWAY_PASSWORD\} ~cdnca:agent-gateway\* -@all \+ping/)
  assert.doesNotMatch(body, /\+@all|allkeys|~\*/)
  assert.match(block('setup_redis'), /remote_gateway_access; then\n\s+configure_redis_gateway_access "\$cli"/)
})

test('nftables only admits the allow-list file on the three Gateway ports', () => {
  const body = block('setup_gateway_access_firewall')
  assert.match(body, /PathChanged=\$\{GATEWAY_ACCESS_FILE\}/)
  for (const rule of ['iif lo accept', 'ip saddr @gateways4 accept', 'ip6 saddr @gateways6 accept', '} drop']) {
    assert.ok(body.includes(rule), rule)
  }
  // Render and run the generated sync script against a recording nft.
  const dir = mkdtempSync(join(tmpdir(), 'gwnft-'))
  try {
    const sync = join(dir, 'sync')
    const allowed = join(dir, 'allowed-ips')
    writeFileSync(allowed, '203.0.113.9\n2001:db8::7\nnot-an-ip;drop\n203.0.113.10\n')
    const heredoc = body.slice(body.indexOf('<<SYNC\n') + 7, body.indexOf('\nSYNC\n'))
    const render = bash([`GATEWAY_ACCESS_FILE=${allowed}`, `cat >${sync} <<SYNC\n${heredoc}\nSYNC`].join('\n'))
    assert.equal(render.status, 0, render.stderr)
    const run = spawnSync('bash', ['-c', `nft() { cat >${dir}/rules; }; export -f nft; bash ${sync}`], { encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    const rules = readFileSync(join(dir, 'rules'), 'utf8')
    assert.match(rules, /set gateways4 \{ type ipv4_addr; elements = \{ 203\.0\.113\.9,203\.0\.113\.10 \}; \}/)
    assert.match(rules, /set gateways6 \{ type ipv6_addr; elements = \{ 2001:db8::7 \}; \}/)
    assert.match(rules, /tcp dport \{ 9446, 4223, 6380 \} drop/)
    assert.doesNotMatch(rules, /not-an-ip/)
    writeFileSync(allowed, '')
    spawnSync('bash', ['-c', `nft() { cat >${dir}/rules; }; export -f nft; bash ${sync}`])
    assert.match(readFileSync(join(dir, 'rules'), 'utf8'), /set gateways4 \{ type ipv4_addr; \}/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('installer flow: control mode adds firewall and keeps the local Gateway; package is published', () => {
  const main = block('main')
  assert.match(main, /! gateway_mode_requested "\$@" \|\| \{ INSTALL_MODE=gateway; gateway_main "\$@"; return; \}\n  parse_args/)
  assert.match(main, /\[ "\$INSTALL_MODE" = all \] \|\| \[ "\$INSTALL_MODE" = control \] \|\| fail/)
  const requested = (args) => spawnSync('bash', ['-c', [block('gateway_mode_requested'), `gateway_mode_requested ${args}`].join('\n')]).status
  assert.equal(requested('--mode gateway --control https://c'), 0)
  assert.equal(requested('--control https://c --mode gateway'), 0)
  assert.notEqual(requested('--mode control'), 0)
  assert.notEqual(requested('--domain gateway'), 0)
  assert.match(main, /generate_gateway_access_secrets\n\s+progress_stage\n\s+download_nats_binaries/)
  assert.match(main, /setup_gateway_access_firewall\n\s+setup_service\n\s+setup_gateway\n\s+publish_gateway_package/)
  assert.match(source, /^readonly NATIVE_RESERVED_PORTS=.* 4223 .* 6380 .* 9446 /m)
  const env = block('write_environment')
  assert.ok(env.includes('! remote_gateway_access || gateway_access_environment >>"${CONFIG_DIR}/control.env"'))
})

test('gateway mode pins the root CA by the token fingerprint and verifies the signed package', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gwpkg-'))
  try {
    const sh = (cmd) => spawnSync('bash', ['-c', cmd], { cwd: dir, encoding: 'utf8' })
    assert.equal(sh(`openssl req -x509 -newkey rsa:2048 -nodes -keyout root-key.pem -out root.pem -subj /CN=root -days 2 2>/dev/null`).status, 0)
    const fingerprint = sh('openssl x509 -in root.pem -outform DER | sha256sum 2>/dev/null || openssl x509 -in root.pem -outform DER | shasum -a 256').stdout.slice(0, 32)
    const token = `gwt1.018f47a2-5b9c-7d31-8a60-104c9c0b717f.${fingerprint}.${'A'.repeat(43)}`
    writeFileSync(join(dir, 'agent-gateway'), 'binary')
    const digest = sh('sha256sum agent-gateway 2>/dev/null || shasum -a 256 agent-gateway').stdout.split(' ')[0]
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ schema: 'cdnca.gateway-package/v1', version: '1.0.35', sha256: digest }))
    assert.equal(sh('openssl dgst -sha256 -sign root-key.pem -out manifest.sig manifest.json').status, 0)
    // curl stub serves files from the fixture directory by URL basename.
    const stub = `curl() { local out="" url=""; while [ $# -gt 0 ]; do case "$1" in --output) out=$2; shift 2;; --cacert|--max-filesize|--connect-timeout|--max-time|--proto|--proto-redir) shift 2;; -*) shift;; *) url=$1; shift;; esac; done; local name=\${url##*/}; [ "$name" = gateway-ca.pem ] && name=root.pem; cp "${dir}/$name" "$out"; }
sha256sum() { if command -v /usr/bin/sha256sum >/dev/null; then /usr/bin/sha256sum "$@"; else shasum -a 256 "$@"; fi; }
install() { local args=("$@"); [ "\${args[0]}" = -d ] && { mkdir -p "\${args[@]: -1}"; return; }; cp "\${args[@]: -2:1}" "\${args[@]: -1}"; }`
    const run = (tokenValue, extra = '') => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), stub,
      block('gateway_fetch_root_ca'), block('gateway_curl'), block('gateway_download_package'), extra,
      `TEMP_DIR=$(mktemp -d) GATEWAY_ROOT=${dir}/root GATEWAY_CONTROL=https://control.example.com GATEWAY_TOKEN='${tokenValue}'`,
      'mkdir -p "$GATEWAY_ROOT/bin"; gateway_fetch_root_ca; gateway_download_package; echo "version=$CONTROL_VERSION"'].join('\n')], { encoding: 'utf8' })
    const ok = run(token)
    assert.equal(ok.status, 0, ok.stderr)
    assert.match(ok.stdout, /version=1\.0\.35/)
    assert.equal(readFileSync(join(dir, 'root', 'bin', 'agent-gateway'), 'utf8'), 'binary')
    const wrong = run(token.replace(fingerprint, '0'.repeat(32)))
    assert.notEqual(wrong.status, 0)
    assert.match(wrong.stderr, /does not match the binding token/)
    writeFileSync(join(dir, 'agent-gateway'), 'tampered')
    const tampered = run(token)
    assert.notEqual(tampered.status, 0)
    assert.match(tampered.stderr, /digest does not match the signed manifest/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('gateway mode reads the token without argv and accepts 443 on a dedicated host', () => {
  const read = (input) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('gateway_read_token'), 'GATEWAY_TOKEN_FILE=- gateway_read_token; echo ok'].join('\n')], { input, encoding: 'utf8' })
  assert.equal(read(`gwt1.018f47a2-5b9c-7d31-8a60-104c9c0b717f.${'a'.repeat(32)}.${'B'.repeat(43)}\n`).status, 0)
  assert.notEqual(read('gwt1.nope\n').status, 0)
  assert.doesNotMatch(block('gateway_parse_args'), /--gateway-token\)/)
  const reserved = source.match(/^readonly NATIVE_RESERVED_PORTS=.*$/m)[0]
  const select = (mode) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), reserved, block('gateway_port_listening'), block('gateway_port_usable'),
    block('gateway_port_suggestion'), block('select_gateway_ports'), 'ss() { :; }',
    `INSTALL_MODE=${mode} GATEWAY_PORTS=443,21444 MASTER_PORT=0 GATEWAY_ENROLLMENT_PORT= GATEWAY_AGENT_PORT=`, 'select_gateway_ports'].join('\n')], { encoding: 'utf8' })
  assert.equal(select('gateway').status, 0, select('gateway').stderr)
  assert.notEqual(select('all').status, 0)
})

test('gateway mode --server-cert/--server-key: both or neither, matching pair, written to the Gateway env', () => {
  const dir = mkdtempSync(join(tmpdir(), 'gw-public-cert-'))
  try {
    const sh = (script) => spawnSync('bash', ['-c', `set -Eeuo pipefail\ncd ${dir}\n${script}`], { encoding: 'utf8' })
    assert.equal(sh(`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem -days 30 -subj /CN=gw.example.com -addext subjectAltName=DNS:gw.example.com 2>/dev/null
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout other.pem -out other-cert.pem -days 30 -subj /CN=x 2>/dev/null`).status, 0)
    const check = (cert, key) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), block('warn'), block('gateway_check_public_certificate'),
      `GATEWAY_HOST=gw.example.com GATEWAY_SERVER_CERT='${cert}' GATEWAY_SERVER_KEY='${key}'`, 'gateway_check_public_certificate; echo ok'].join('\n')], { encoding: 'utf8' })
    assert.equal(check('', '').status, 0)
    assert.equal(check(join(dir, 'cert.pem'), join(dir, 'key.pem')).status, 0, check(join(dir, 'cert.pem'), join(dir, 'key.pem')).stderr)
    assert.match(check(join(dir, 'cert.pem'), '').stderr, /given together/)
    assert.match(check(join(dir, 'cert.pem'), join(dir, 'other.pem')).stderr, /do not match/)
    assert.match(check(join(dir, 'other-cert.pem'), join(dir, 'other.pem')).stderr, /does not name gw\.example\.com/)
    const service = block('gateway_write_service')
    assert.match(service, /^  gateway_install_public_certificate$/m)
    assert.match(service, /CDNCA_GATEWAY_TUNNEL_TLS_CERT_FILE=%s/)
    assert.match(service, /CDNCA_GATEWAY_TUNNEL_TLS_KEY_FILE=%s/)
    assert.match(block('gateway_install_public_certificate'), /install -m 0600 "\$GATEWAY_SERVER_KEY"/)
    // Checked before the one-time token is read and consumed.
    const main = block('gateway_main')
    assert.ok(main.indexOf('gateway_check_public_certificate') < main.indexOf('gateway_read_token'))
    assert.match(block('gateway_parse_args'), /--server-cert\)/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
