// install-node.sh check 子命令覆盖节点合同
// （agent/helper active、KillMode=process、打包单元、网关会话、install-state、openresty -V、luajit、
// config 关键开关），全新装完 check 必须全过，任何一项坏了非 0。
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const source = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
const script = source.replace(/^main "\$@"\s*$/m, '')

function isolate(root) {
  let isolated = script
  for (const prefix of ['/usr/local', '/etc', '/opt', '/var/lib', '/var/log', '/run']) {
    isolated = isolated.replace(new RegExp(`${prefix}(?=/|["'\\s;]|$)`, 'g'), join(root, prefix.slice(1)))
  }
  for (const prefix of ['/usr/lib/cdnca-edge-agent', '/usr/lib/systemd/system', '/usr/libexec/cdnca-edge-agent-helper', '/usr/libexec/cdnca-edge-agent']) {
    isolated = isolated.replaceAll(`"${prefix}`, `"${join(root, prefix.slice(1))}`)
  }
  return isolated
}

const stubs = `
systemctl() {
  case "$*" in
    'is-active --quiet cdnca-edge-agent') [ "\${FX_AGENT:-active}" = active ] ;;
    'is-active --quiet cdnca-edge-agent-helper.socket') [ "\${FX_HELPER:-active}" = active ] ;;
    'show cdnca-edge-agent -p KillMode --value') printf '%s\\n' "\${FX_KILLMODE:-process}" ;;
    'show cdnca-edge-agent -p NRestarts --value') printf '0\\n' ;;
    'show cdnca-edge-agent -p InvocationID --value') printf 'inv1\\n' ;;
    'show cdnca-edge-agent -p FragmentPath --value') printf '%s\\n' "\${FX_FRAGMENT:-$SYSTEMD_PACKAGE_DIR/cdnca-edge-agent.service}" ;;
    *) return 1 ;;
  esac
}
journalctl() { printf '%s\\n' "\${FX_JOURNAL:-}"; }
ss() { case "$*" in *-Hltn*) printf '%s' "\${FX_LISTEN:-}" ;; *) printf '%s\\n' "\${FX_SS:-}" ;; esac; }
ip() { :; }
curl() { printf '%s' "\${FX_HEALTH:-204}"; }
`

function fixture(overrides = {}) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-node-check-'))
  const file = (path, contents, mode = 0o600) => {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, contents)
    chmodSync(target, mode)
    return target
  }
  const config = {
    version: 2, gateway: { address: 'gateway.example:19444', transport: 'grpc' },
    openresty: { version: '1.31.1.1' }, dynamic_routing: { enabled: true }, security_runtime: { mode: 'native' },
    upgrade: { enabled: true }, ...overrides.config,
  }
  file('etc/cdnca-edge-agent/config.json', JSON.stringify(config), overrides.configMode ?? 0o600)
  file('etc/cdnca-edge-agent/identity/identity.json', JSON.stringify({ version: 1, node_id: '9b1c0f9e-0000-4000-8000-000000000001' }))
  for (const name of ['trust/control-execution.json', 'trust/edge-execution.json', 'trust/installer-receipt.json', 'trust/artifacts.json', 'tls/upgrade-download-ca.pem']) {
    file(`etc/cdnca-edge-agent/${name}`, '{}', 0o400)
  }
  file('usr/lib/systemd/system/cdnca-edge-agent.service', '[Service]\n', 0o644)
  file('var/lib/cdnca-node-install/state', overrides.state ?? `schema=cdnca.node-install-state/v1\nmanifest_sha256=${'a'.repeat(64)}\nstep=packaged\nstep=done\n`)
  file('var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/installation-ban/state.json',
    JSON.stringify({ schema: 'cdnca.edge.installation-ban-state/v1', status: overrides.banStatus ?? 'serving', stopped: false }))
  const keys = 'signerKeys' in overrides ? overrides.signerKeys : [{ key_id: 'cdnca-license-1', public_key_pem: 'pem', usage: 'installation-ban' }]
  if (keys !== null) {
    const signed = JSON.stringify({ document: { schema: 'cdnca.edge-signer-trust/v1', revision: 1, issued_at: '2026-11-01T00:00:00Z', trusted_keys: keys, revoked_keys: [] }, envelope: {}, signature: 'x' })
    file('var/lib/cdnca-edge-agent-backups/active-state/gateway-journal/signer-trust/state.json',
      JSON.stringify({ schema: 'cdnca.edge.signer-trust-state/v1', revision: 1, document: Buffer.from(signed).toString('base64'), applied_at: '2026-11-01T00:00:00Z' }))
  }
  const version = overrides.openresty ?? 'nginx version: openresty/1.31.1.1\nconfigure arguments: --with-http_v3_module --add-module=../ngx_http_ja4_module'
  file('usr/local/openresty/bin/openresty', `#!/usr/bin/env bash\ncat >&2 <<'EOF'\n${version}\nEOF\n`, 0o755)
  if (overrides.luajit !== false) file('opt/cdnca-node/current/runtime/openresty/luajit/bin/luajit', '#!/bin/sh\n', 0o755)
  return root
}

function check(overrides = {}, env = {}, lang = 'zh') {
  const root = fixture(overrides)
  try {
    const body = `${isolate(root)}\n${stubs}\ninstall_lang_init --lang ${lang}\ncheck_installed`
    return spawnSync('bash', ['-c', body], {
      encoding: 'utf8', timeout: 20000,
      env: { PATH: process.env.PATH, FX_SS: 'ESTAB 0 0 10.0.0.2:51234 203.0.113.20:19444 users:(("edge-agent",pid=12,fd=9))', ...env },
    })
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

test('a healthy fresh node passes every check item', () => {
  const result = check()
  assert.equal(result.status, 0, result.stdout + result.stderr)
  for (const item of ['cdnca-edge-agent active', 'cdnca-edge-agent-helper.socket active', 'KillMode=process', '打包单元',
    '网关会话', 'install-state', 'openresty 1.31.1.1', 'http_v3', 'JA4', 'luajit', 'dynamic_routing']) {
    assert.ok(result.stdout.includes(item), `missing ${item}\n${result.stdout}`)
  }
  assert.doesNotMatch(result.stderr, /warning/)
})

test('English check output has no Chinese', () => {
  const result = check({}, {}, 'en')
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.doesNotMatch(result.stdout + result.stderr, /\p{Script=Han}/u)
})

const broken = [
  ['agent inactive', {}, { FX_AGENT: 'failed' }, /cdnca-edge-agent 不是 active/],
  ['helper socket inactive', {}, { FX_HELPER: 'failed' }, /cdnca-edge-agent-helper\.socket 不是 active/],
  ['KillMode', {}, { FX_KILLMODE: 'control-group' }, /KillMode=control-group/],
  ['unit shadowed in /etc', {}, { FX_FRAGMENT: '/etc/systemd/system/cdnca-edge-agent.service' }, /打包单元/],
  ['no gateway session', {}, { FX_SS: '', FX_JOURNAL: 'gateway session ended; reconnecting established=false' }, /网关会话/],
  ['install not finished', { state: 'schema=cdnca.node-install-state/v1\nstep=packaged\n' }, {}, /--resume/],
  ['openresty version', { openresty: 'nginx version: openresty/1.27.1.2\n--with-http_v3_module ja4' }, {}, /openresty/],
  ['no http3 module', { openresty: 'nginx version: openresty/1.31.1.1\nconfigure arguments: ja4' }, {}, /http_v3/],
  ['luajit missing', { luajit: false }, {}, /luajit/],
  ['dynamic routing off', { config: { dynamic_routing: { enabled: false } } }, {}, /dynamic_routing/],
  ['config readable by others', { configMode: 0o644 }, {}, /config\.json/],
  ['health answers 502 while listening', {}, { FX_LISTEN: 'LISTEN 0 511 127.0.0.1:18080 0.0.0.0:*', FX_HEALTH: '502' }, /healthz/],
]
for (const [name, overrides, env, pattern] of broken) {
  test(`check fails: ${name}`, () => {
    const result = check(overrides, env)
    assert.equal(result.status, 1, result.stdout + result.stderr)
    assert.match(result.stderr, pattern)
  })
}

test('the gateway session may come from the journal of this Agent start (ws tunnel through 443)', () => {
  const result = check({ config: { gateway: { address: 'gateway.example:443', transport: 'ws' } } },
    { FX_SS: '', FX_JOURNAL: 'node network inventory report ipv4_state=1' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
})

test('health port not listening before the first site is only reported', () => {
  const result = check({}, { FX_LISTEN: '' })
  assert.equal(result.status, 0, result.stdout + result.stderr)
  assert.match(result.stdout, /18080/)
})

test('main dispatches the check subcommand before parsing install options', () => {
  const main = source.slice(source.indexOf('main() {'))
  assert.match(main, /install_lang_init "\$@"\n\s+set -- .*\n\s+if \[ "\$\{1:-\}" = check \]/)
  assert.match(source, /install-node\.sh check/) // usage documents it
})
