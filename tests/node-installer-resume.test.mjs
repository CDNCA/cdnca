import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

// freeze-audit X7（triage-2 S1）：PJ-E05 服务起来不等于连上主控；PJ-E06 半途失败后可 --resume 续装；
// PJ-E07 主控地址是 IPv6 字面量时正确解析。
const source = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
const script = source.replace(/^main "\$@"\s*$/m, '')

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-node-resume-'))
  let isolated = script
  for (const prefix of ['/usr/local', '/etc', '/opt', '/var/lib', '/var/log', '/run', '/usr/sbin/nginx']) {
    isolated = isolated.replace(new RegExp(`${prefix}(?=/|["'\\s;]|$)`, 'g'), join(root, prefix.slice(1)))
  }
  for (const prefix of ['/usr/lib/cdnca-edge-agent', '/usr/lib/systemd/system', '/usr/libexec/cdnca-edge-agent-helper', '/usr/libexec/cdnca-edge-agent']) {
    isolated = isolated.replaceAll(`"${prefix}`, `"${join(root, prefix.slice(1))}`)
  }
  const file = (path, contents, mode = 0o600) => {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, contents, { mode })
    return target
  }
  const run = (body, env = {}) => spawnSync('bash', ['-c', `${isolated}\n${body}`, 'fixture', root],
    { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 15000 })
  return { root, file, run }
}

// 空机门禁需要的宿主外观（与 native-node-installer.test.mjs 相同的打桩）。
const hostStubs = `
uname() { if [[ "$1" == -s ]]; then printf Linux; else printf x86_64; fi; }
systemctl() { if [[ "$*" == *cdnca-edge-agent* && -n "\${FIXTURE_AGENT_UNIT:-}" ]]; then printf 'loaded\\n'; else printf 'not-found\\n'; fi; }
flock() { return 0; }
stat() { printf '0:1:600\\n'; }
`
function hostFixture() {
  const value = fixture()
  value.file('etc/os-release', 'ID=ubuntu\nVERSION_ID="24.04"\n')
  mkdirSync(join(value.root, 'run/systemd/system'), { recursive: true })
  mkdirSync(join(value.root, 'run/lock'), { recursive: true })
  mkdirSync(join(value.root, 'var/lib'), { recursive: true })
  return value
}
// 上次运行在节点注册前失败后留下的半成品（cleanup 已撤链接、停服务，保留发布目录与打包产物）。
function halfInstalled(value, steps = []) {
  value.file('var/lib/cdnca-node-install/state', ['schema=cdnca.node-install-state/v1', `manifest_sha256=${'a'.repeat(64)}`, ...steps, ''].join('\n'))
  mkdirSync(join(value.root, 'opt/cdnca-node/releases', 'a'.repeat(64)), { recursive: true })
  mkdirSync(join(value.root, 'etc/cdnca-edge-agent/trust'), { recursive: true })
  mkdirSync(join(value.root, 'usr/lib/cdnca-edge-agent/versions/1.2.3'), { recursive: true })
}

test('PJ-E06 repro: rerunning the original command after a half install points to --resume', () => {
  const value = hostFixture()
  try {
    halfInstalled(value)
    const result = value.run(`${hostStubs}\nassert_blank_host`, { FIXTURE_AGENT_UNIT: '1' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /上次节点安装未完成.*--resume/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('PJ-E06: --resume continues only this installer\'s own half install', () => {
  const value = hostFixture()
  try {
    halfInstalled(value)
    const resumed = value.run(`${hostStubs}\nRESUME=true\nassert_blank_host\nprintf passed`, { FIXTURE_AGENT_UNIT: '1' })
    assert.equal(resumed.status, 0, resumed.stderr)
    assert.match(resumed.stdout, /passed$/)
    // 不是本安装器建的东西照样拒绝
    mkdirSync(join(value.root, 'var/lib/site-runtime'), { recursive: true })
    const foreign = value.run(`${hostStubs}\nRESUME=true\nassert_blank_host`, { FIXTURE_AGENT_UNIT: '1' })
    assert.notEqual(foreign.status, 0)
    assert.match(foreign.stderr, /resume refused: .*site-runtime/)
    rmSync(join(value.root, 'var/lib/site-runtime'), { recursive: true })
    mkdirSync(join(value.root, 'usr/local'), { recursive: true })
    symlinkSync('/somewhere/else', join(value.root, 'usr/local/openresty'))
    const link = value.run(`${hostStubs}\nRESUME=true\nassert_blank_host`, { FIXTURE_AGENT_UNIT: '1' })
    assert.notEqual(link.status, 0)
    assert.match(link.stderr, /resume refused: .*openresty/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('PJ-E06: --resume is refused without a record or after a completed install', () => {
  const value = hostFixture()
  try {
    const none = value.run(`${hostStubs}\nRESUME=true\nassert_blank_host`)
    assert.notEqual(none.status, 0)
    assert.match(none.stderr, /本机没有安装记录/)
    halfInstalled(value, ['step=done'])
    const done = value.run(`${hostStubs}\nRESUME=true\nassert_blank_host`, { FIXTURE_AGENT_UNIT: '1' })
    assert.notEqual(done.status, 0)
    assert.match(done.stderr, /已安装完成/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('PJ-E06: a first install records its state right after the blank host gate', () => {
  const value = hostFixture()
  try {
    const result = value.run(`${hostStubs}\nassert_blank_host\ninstall_state_begin\ninstall_state_add step=packaged\ninstall_state_has step=packaged && printf has`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, 'has')
    const state = readFileSync(join(value.root, 'var/lib/cdnca-node-install/state'), 'utf8')
    assert.match(state, /^schema=cdnca\.node-install-state\/v1\nstep=packaged\n$/)
    assert.equal(lstatSync(join(value.root, 'var/lib/cdnca-node-install/state')).mode & 0o777, 0o600)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

const linkStubs = `
ln() { if [[ "$1" == -sT ]]; then shift; [[ ! -e "$2" && ! -L "$2" ]] || return 1; command ln -s "$@"; else command ln "$@"; fi; }
mv() { if [[ "$1" == -T ]]; then shift; fi; command mv "$@"; }
`
function activationFixture(value, stageContent) {
  value.file('stage/bin/edge-agent', stageContent)
  value.file('temporary/artifacts.json', '{}')
  value.file('temporary/gateway-ca.pem', 'fixture certificate')
  for (const name of ['control-execution.json', 'edge-execution.json', 'download-ca.pem']) value.file(`temporary/upgrade-trust/${name}`, name, 0o400)
}
const activate = `TEMP_DIR="$1/temporary"; NATIVE_STAGE="$1/stage"; NATIVE_MANIFEST_SHA=${'a'.repeat(64)}
ARTIFACT_TRUST_FILE="$1/temporary/artifacts.json"; GATEWAY_ROOT_CA_FILE="$1/temporary/gateway-ca.pem"
activate_native_package`

test('PJ-E06: resumed activation reuses the identical retained release and recreates the links', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    value.file(`opt/cdnca-node/releases/${'a'.repeat(64)}/bin/edge-agent`, 'verified fixture')
    activationFixture(value, 'verified fixture')
    const result = value.run(`${linkStubs}\nRESUME=true\n${activate}\nprintf ok`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(readlinkSync(join(value.root, 'opt/cdnca-node/current')), `releases/${'a'.repeat(64)}`)
    assert.equal(existsSync(join(value.root, 'stage')), false)
    // 保留的发布目录与本次重新校验的副本不一致：拒绝
    value.file('stage/bin/edge-agent', 'other bytes')
    unlinkSync(join(value.root, 'opt/cdnca-node/current'))
    const differs = value.run(`${linkStubs}\nRESUME=true\n${activate}`)
    assert.notEqual(differs.status, 0)
    assert.match(differs.stderr, /differs from this run's verified package/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('PJ-E06: resume refuses a different node package than the half install', () => {
  const value = fixture()
  try {
    halfInstalled(value)
    value.file('var/lib/cdnca-node-install/state', `schema=cdnca.node-install-state/v1\nmanifest_sha256=${'b'.repeat(64)}\n`)
    activationFixture(value, 'verified fixture')
    const result = value.run(`${linkStubs}\nRESUME=true\n${activate}`)
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /与上次.*不同/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('PJ-E06: completed packaging is skipped on resume; enrollment is skipped once the identity exists', () => {
  const value = fixture()
  try {
    halfInstalled(value, ['step=packaged'])
    mkdirSync(join(value.root, 'usr/lib/cdnca-edge-agent'), { recursive: true })
    symlinkSync('versions/1.2.3', join(value.root, 'usr/lib/cdnca-edge-agent/current'))
    const result = value.run(`RESUME=true; NATIVE_VERSION=1.2.3; NATIVE_RELEASE="$1/missing-release"\ninstall_agent_packaging\nprintf skipped`)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.endsWith('skipped'), true)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
  const main = source.slice(source.indexOf('\nmain() {'))
  assert.match(main, /if "\$RESUME" && \[ -f "\$\{IDENTITY_DIR\}\/identity\.json" \]; then[\s\S]*?else\n[\s\S]*?\n {4}if \[ -n "\$REGISTRATION_KEY" \]; then register_node; fi\n {4}enroll\n/)
  assert.match(main, /\n {2}assert_blank_host\n {2}"\$RESUME" \|\| install_state_begin\n/)
  assert.match(main, /\n {2}setup_service\n {2}verify_agent_connected\n {2}install_state_add step=done\n/)
  assert.match(source, /--resume\) RESUME=true; shift ;;/)
})

// PJ-E07
function defaults(controlPlane, extra = '') {
  const rootless = script.replace(`[ "$EUID" -eq 0 ] || fail 'run this installer as root'`, ':')
  return spawnSync('bash', ['-c', `${rootless}
parse_args --control-plane '${controlPlane}' --enrollment-token fixture-token --upgrade-trust-sha256 ${'ab'.repeat(32)} ${extra}
normalise_defaults
printf '%s|%s|%s|%s|%s' "$MASTER_HOST" "$MASTER_PORT" "$GATEWAY_ENROLLMENT_ADDRESS" "$GATEWAY_ADDRESS" "$GATEWAY_SERVER_NAME"`], { encoding: 'utf8' })
}

test('PJ-E07: an IPv6 literal control plane yields bracketed gateway addresses and the bare host', () => {
  for (const [url, expected] of [
    ['https://[2001:db8::1]:8443/console', '2001:db8::1|8443|[2001:db8::1]:19443|[2001:db8::1]:19444|2001:db8::1'],
    ['https://[2001:0:0::1]', '2001:0:0::1|443|[2001:0:0::1]:19443|[2001:0:0::1]:19444|2001:0:0::1'],
    ['https://[::ffff:203.0.113.9]:9443', '::ffff:203.0.113.9|9443|[::ffff:203.0.113.9]:19443|[::ffff:203.0.113.9]:19444|::ffff:203.0.113.9'],
    ['https://203.0.113.9:8443', '203.0.113.9|8443|203.0.113.9:19443|203.0.113.9:19444|203.0.113.9'],
    ['https://console.example.com/', 'console.example.com|443|console.example.com:19443|console.example.com:19444|console.example.com'],
  ]) {
    const result = defaults(url)
    assert.equal(result.status, 0, `${url}: ${result.stderr}`)
    assert.equal(result.stdout, expected, url)
    // 生成的地址要能通过安装器自己对网关地址的校验（gateway_endpoints_json / 主控默认值）
    for (const address of result.stdout.split('|').slice(2, 4)) {
      assert.match(address, /^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$/, address)
    }
  }
  const bracketed = defaults('https://console.example.com', '--master-host [2001:db8::2]')
  assert.equal(bracketed.stdout, '2001:db8::2|443|[2001:db8::2]:19443|[2001:db8::2]:19444|2001:db8::2')
})

test('PJ-E07: an unbracketed IPv6 control plane is rejected with the bracket form', () => {
  const result = defaults('https://2001:db8::1/')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /IPv6 .*https:\/\/\[2001:db8::1\]/)
})

// PJ-E05
function session({ journal = '', active = 'active', listening = false, healthy = true }) {
  const value = fixture()
  value.file('journal', journal)
  const result = value.run(`
log() { printf 'LOG %s\\n' "$*" >&2; }
progress_tick() { :; }; sleep() { :; }
systemctl() { [[ "$1" == is-active ]] && [[ "$FIXTURE_ACTIVE" == active ]]; }
journalctl() { [[ "$*" == *"--since 2026-10-26 10:00:00"* ]] || return 64; cat "$FIXTURE_JOURNAL"; }
timeout() { shift; [[ "$*" == *18080* ]] && [[ -n "$FIXTURE_LISTENING" ]]; }
curl() { [[ "$*" == *"http://127.0.0.1:18080/healthz"* ]] && [[ -n "$FIXTURE_HEALTHY" ]]; }
cleanup() { printf 'KEEP=%s\\n' "$INSTALL_KEEP" >&2; }
GATEWAY_SESSION_WAIT_SECONDS=1; GATEWAY_ADDRESS='[2001:db8::1]:19444'; AGENT_STARTED_AT='2026-10-26 10:00:00'
verify_agent_connected
printf connected`, { FIXTURE_JOURNAL: join(value.root, 'journal'), FIXTURE_ACTIVE: active, FIXTURE_LISTENING: listening ? '1' : '', FIXTURE_HEALTHY: healthy ? '1' : '' })
  rmSync(value.root, { recursive: true, force: true })
  return result
}

test('PJ-E05: the install completes only after this Agent start held a Gateway session', () => {
  const ok = session({ journal: '2026/10/26 10:00:03 INFO node network inventory report ipv4_state=accepted ipv6_state=absent\n' })
  assert.equal(ok.status, 0, ok.stderr)
  assert.match(ok.stderr, /已与主控网关 \[2001:db8::1\]:19444 建立会话/)
  assert.match(ok.stderr, /健康端口 127\.0\.0\.1:18080 尚未监听/)
  const healthy = session({ journal: 'WARN gateway session ended; reconnecting established=true retry_in=1s\n', listening: true })
  assert.equal(healthy.status, 0, healthy.stderr)
  assert.match(healthy.stderr, /本机健康检查通过/)
})

test('PJ-E05: no Gateway session says the service runs but is not connected, keeps it and explains', () => {
  const result = session({ journal: '2026/10/26 10:00:03 WARN gateway session ended; reconnecting established=false retry_in=2s error="connection refused"\n' })
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /服务已起但未连上主控网关 \[2001:db8::1\]:19444/)
  assert.match(result.stderr, /最近一次错误：.*connection refused/)
  assert.match(result.stderr, /放行 TCP 19444/)
  assert.match(result.stderr, /--resume/)
  assert.match(result.stderr, /KEEP=true/)
  const unhealthy = session({ journal: 'INFO node network inventory report state=rejected code=PermissionDenied\n', listening: true, healthy: false })
  assert.notEqual(unhealthy.status, 0)
  assert.match(unhealthy.stderr, /健康检查失败/)
  assert.match(unhealthy.stderr, /KEEP=true/)
  const stopped = session({ active: 'failed' })
  assert.notEqual(stopped.status, 0)
  assert.match(stopped.stderr, /edge-agent 启动后又退出/)
  assert.match(stopped.stderr, /KEEP=false/)
})

test('PJ-E05: the session evidence matches what the Agent logs', () => {
  const inventory = readFileSync(new URL('../agents/edge-agent/internal/gatewayclient/node_inventory.go', import.meta.url), 'utf8')
  const client = readFileSync(new URL('../agents/edge-agent/internal/gatewayclient/client.go', import.meta.url), 'utf8')
  assert.match(inventory, /slog\.(Info|Warn)\("node network inventory report"/)
  assert.match(client, /slog\.Warn\("gateway session ended; reconnecting", "established", established/)
  // 清单上报只在 GatewayHello 校验通过之后才发起
  const session = client.slice(client.indexOf('func (c *Client) runSession('))
  assert.ok(session.indexOf('validateGatewayHello(') < session.indexOf('c.runNodeInventory('))
})

// fz-x13：上次的网关注册已在主控签发证书、本机没写下身份文件时，--resume 用注册凭据取回身份，
// 不再重复注册；主控查不到（404）就回到原流程；一次性令牌安装的节点只提示删节点重装。
function recoverFixture() {
  const value = fixture()
  mkdirSync(join(value.root, 'etc/cdnca-edge-agent/identity.enrolling'), { recursive: true, mode: 0o700 })
  value.file('etc/cdnca-edge-agent/identity.enrolling/pending.json', '{}')
  // 假 Agent：打印 CSR 摘要；取回时校验响应文件并写出 identity.json。
  value.file('usr/lib/cdnca-edge-agent/current/edge-agent', `#!/bin/bash
printf '%s\\n' "$*" >>"$FIXTURE_ROOT/agent-calls"
case "$2" in
  --print-pending-csr-sha256) printf '%s\\n' ${JSON.stringify('cd'.repeat(32))} ;;
  --recover-from-response)
    [ -z "$FIXTURE_AGENT_REJECT" ] || exit 1
    grep -q node_id "$3" || [ ! -s "$3" ] || exit 1
    mkdir -p "$FIXTURE_ROOT/etc/cdnca-edge-agent/identity" && printf '{}' >"$FIXTURE_ROOT/etc/cdnca-edge-agent/identity/identity.json"
    printf '{"node_id":"n"}\\n' ;;
esac
`, 0o755)
  const run = (env = {}) => value.run(`
machine_fingerprint() { printf '%s' ${JSON.stringify('a1'.repeat(32))}; }
curl_download() {
  local url=$1 out=''; shift
  while [ "$#" -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; --data-binary) cp "\${2#@}" "$FIXTURE_ROOT/request.json"; shift 2 ;; *) shift ;; esac; done
  printf '%s\\n' "$url" >>"$FIXTURE_ROOT/curl-calls"
  printf '%s' "$FIXTURE_BODY" >"$out"; printf '%s' "$FIXTURE_STATUS"
}
TEMP_DIR="$1/tmp-install"; mkdir -p "$TEMP_DIR"; CONTROL_PLANE=https://ctl.example; REGISTRATION_KEY=nrk1.fixture
if recover_registered_identity; then printf 'recovered:%s' "\${REGISTRATION_KEY:-unset}"; else printf 'fallback'; fi`,
  { FIXTURE_ROOT: value.root, ...env })
  return { ...value, run }
}

test('fz-x13: --resume fetches the issued identity and skips registration', () => {
  const value = recoverFixture()
  try {
    const result = value.run({ FIXTURE_STATUS: '200', FIXTURE_BODY: '{"node_id":"018f47a2-5b9c-7d31-8a60-104c9c0b717f"}' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.endsWith('recovered:unset'), true, result.stdout)
    assert.match(readFileSync(join(value.root, 'curl-calls'), 'utf8'), /^https:\/\/ctl\.example\/v1\/node-registrations\/identity\n$/)
    const request = JSON.parse(readFileSync(join(value.root, 'request.json'), 'utf8'))
    assert.deepEqual(request, { credential: 'nrk1.fixture', machine_fingerprint: 'a1'.repeat(32), csr_sha256: 'cd'.repeat(32) })
    assert.match(readFileSync(join(value.root, 'agent-calls'), 'utf8'), /--recover-from-response \S+identity-response\.json --identity-dir/)
    assert.equal(existsSync(join(value.root, 'tmp-install/identity-response.json')), false, 'response with the certificate must be removed')
    assert.equal(existsSync(join(value.root, 'tmp-install/identity-request.json')), false, 'request with the credential must be removed')
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('fz-x13: 404 falls back to register + enroll; a bad credential stops', () => {
  const value = recoverFixture()
  try {
    const missing = value.run({ FIXTURE_STATUS: '404', FIXTURE_BODY: '{"error":{"code":"node_identity_not_found"}}' })
    assert.equal(missing.status, 0, missing.stderr)
    assert.equal(missing.stdout.endsWith('fallback'), true)
    assert.match(missing.stdout, /主控没有本机已签发的身份，按原流程注册/)
    assert.equal(existsSync(join(value.root, 'etc/cdnca-edge-agent/identity')), false)
    const stale = value.run({ FIXTURE_STATUS: '401', FIXTURE_BODY: '{"error":{"code":"invalid_registration_credential"}}' })
    assert.notEqual(stale.status, 0)
    assert.match(stale.stderr, /注册凭据无效或已被重置/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('fz-x13: an identity that does not match the pending keys stops with delete-and-reinstall', () => {
  const value = recoverFixture()
  try {
    const result = value.run({ FIXTURE_STATUS: '200', FIXTURE_BODY: '{"node_id":"x"}', FIXTURE_AGENT_REJECT: '1' })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /请到管理端删除该节点后重装/)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('fz-x13: a half-committed identity directory is committed without calling the controller', () => {
  const value = recoverFixture()
  try {
    unlinkSync(join(value.root, 'etc/cdnca-edge-agent/identity.enrolling/pending.json'))
    value.file('etc/cdnca-edge-agent/identity.enrolling/identity.json', '{}')
    const result = value.run({ FIXTURE_STATUS: '500', FIXTURE_BODY: '' })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout.endsWith('recovered:unset'), true, result.stdout)
    assert.equal(existsSync(join(value.root, 'curl-calls')), false)
  } finally { rmSync(value.root, { recursive: true, force: true }) }
})

test('fz-x13: main recovers only on --resume with pending state and a registration credential', () => {
  const main = source.slice(source.indexOf('\nmain() {'))
  assert.match(main, /elif "\$RESUME" && \[ -d "\$\{IDENTITY_DIR\}\.enrolling" \] && \[ -n "\$REGISTRATION_KEY" \] && recover_registered_identity; then/)
  assert.match(main, /用一次性安装令牌安装的节点无法从主控取回已签发的身份[^\n]*请到管理端删除该节点后重装/)
})
