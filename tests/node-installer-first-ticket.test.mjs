import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

// PF09（用户 10-24 23:5x Q2）：节点拿到首张授权签名凭据之前不对外开放。安装器在服务稳定后等首票，
// 收到即报告开放；超时不回滚（Agent 仍在等凭据，到达后自动开放），但不再报成功（Codex 10-26 P2）：
// 退出码 3、机器可读的 install-state 行、原因与排查办法，安装记录不写 step=done，修好后 --resume 重新自检。
const source = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')

function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function run(status, adminState = '', stopped = false) {
  const dir = mkdtempSync(join(tmpdir(), 'node-first-ticket-'))
  const state = join(dir, 'installation-ban', 'state.json')
  mkdirSync(join(dir, 'installation-ban'))
  if (status) writeFileSync(state, JSON.stringify({ schema: 'cdnca.edge.installation-ban-state/v1', status, stopped }))
  const script = ['set -Eeuo pipefail', 'log() { printf "LOG %s\\n" "$*" >&2; }', 'warn() { printf "WARN %s\\n" "$*" >&2; }',
    'progress_tick() { printf "TICK\\n" >&2; }', 'sleep() { :; }', `INSTALLATION_BAN_STATE=${JSON.stringify(state)}`, 'FIRST_TICKET_WAIT_SECONDS=1',
    'SERVICE_NAME=cdnca-edge-agent', 'INSTALL_KEEP=false', `REGISTERED_ADMIN_STATE=${JSON.stringify(adminState)}`, 'readonly FIRST_TICKET_EXIT_CODE=3',
    'INSTALLER_COPY=/var/lib/cdnca-node-install/install-node.sh', block('node_next_steps'), block('installation_ban_status'), block('wait_first_ticket'), 'PROGRESS_EXIT_NOTICE=\'\'', 'trap \'printf "KEEP %s\\n" "$INSTALL_KEEP" >&2; [ -z "$PROGRESS_EXIT_NOTICE" ] || printf "NOTICE %s\\n" "$PROGRESS_EXIT_NOTICE" >&2\' EXIT', 'wait_first_ticket'].join('\n')
  return spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH } })
}

test('a node that received its first ticket is reported open', () => {
  const result = run('serving')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /LOG first license service ticket received/)
  assert.match(result.stderr, /LOG install-state: serving/)
})

// Codex 复查卡 9：凭据已生效（status=serving）但 Agent 恢复服务失败时，状态文件仍是 stopped=true，
// 节点实际仍是 503/四层关闭，不能报 install-state: serving。
test('a ticket that arrived but whose resume failed (stopped=true) is not reported as serving', () => {
  for (const adminState of ['', 'pending']) {
    const result = run('serving', adminState, true)
    assert.equal(result.status, 3, result.stderr)
    assert.doesNotMatch(result.stderr, /LOG install-state: serving/)
    assert.doesNotMatch(result.stderr, /the node serves traffic/)
    // INSTALL-P2-02：注册时的 pending 快照不能盖住实时已知的恢复失败。
    assert.match(result.stdout, /install-state: installed_resume_failed$/m)
    assert.doesNotMatch(result.stdout, /installed_pending_initialization/)
    assert.match(result.stderr, /error: 授权签名凭据已生效，但节点恢复对外服务失败.*journalctl -u cdnca-edge-agent/s)
    assert.doesNotMatch(result.stderr, /尚未初始化/)
    assert.match(result.stderr, /KEEP true/)
  }
})

test('no first ticket: the install fails with the state, the cause, what to check and --resume, keeping the service', () => {
  for (const status of [null, 'no_ticket']) {
    const result = run(status)
    assert.equal(result.status, 3, result.stderr)
    assert.match(result.stdout, /^\[cdnca-edge\] install-state: installed_pending_ticket$/m)
    assert.match(result.stderr, /error: 节点已安装，1 秒内授权签名凭据仍未生效，暂不对外服务/)
    assert.match(result.stderr, /待初始化.*初始化/)
    assert.doesNotMatch(result.stderr, /「授权凭据」列/) // the node list no longer has that column (9a4a28d36)
    assert.match(result.stderr, /journalctl -u cdnca-edge-agent/)
    assert.match(result.stderr, /Agent 服务保持运行.*--resume 重新自检/)
    assert.match(result.stderr, /KEEP true/) // cleanup must not roll the install back
  }
  for (const [status, state, text] of [['banned', 'installed_banned', /本主控安装已被授权方停用/],
    ['service_ticket_expired', 'installed_ticket_expired', /节点持有的授权签名凭据已过期/]]) {
    const result = run(status)
    assert.equal(result.status, 3, result.stderr)
    assert.match(result.stdout, new RegExp(`install-state: ${state}$`, 'm'))
    assert.match(result.stderr, text)
  }
})

// 节点未初始化时不空等首票。注册响应里 node.admin_state=pending 的节点在初始化前拿不到票据，
// 直接报 installed_pending_initialization、退出码 3、保留服务，不再等满 FIRST_TICKET_WAIT_SECONDS。
test('a node registered as pending is reported pending initialization at once, keeping the service', () => {
  for (const status of [null, 'no_ticket']) {
    const result = run(status, 'pending')
    assert.equal(result.status, 3, result.stderr)
    assert.match(result.stdout, /^\[cdnca-edge\] install-state: installed_pending_initialization$/m)
    assert.doesNotMatch(result.stdout, /installed_pending_ticket/)
    assert.doesNotMatch(result.stderr, /TICK/) // no waiting for the ticket
    assert.match(result.stderr, /\[cdnca-edge\] 安装完成，待主控初始化：节点已连上主控/)
    assert.doesNotMatch(result.stderr, /error:/) // expected state, not a failure
    assert.match(result.stderr, /节点列表 → 待初始化.*初始化/)
    assert.match(result.stderr, /初始化后主控自动下发授权签名凭据，节点自动开放/)
    assert.match(result.stderr, /--resume 只用来复核，不是必须执行/)
    assert.match(result.stderr, /NOTICE 安装完成，待主控初始化（退出码 3 表示此状态，不是失败）/)
    assert.match(result.stderr, /KEEP true/)
  }
  // Already serving (initialized meanwhile), or not registered in this run (resume, token): the normal wait.
  assert.equal(run('serving', 'pending').status, 0)
  const resumed = run(null, '')
  assert.equal(resumed.status, 3)
  assert.match(resumed.stderr, /TICK/)
  assert.match(resumed.stdout, /install-state: installed_pending_ticket$/m)
})

// INSTALL-P2-02：注册为 pending 之后状态文件已有明确结论（封禁/凭据过期）时按实时状态报，不再一律指向初始化。
test('a definite current state wins over the pending registration snapshot', () => {
  for (const [status, state, text] of [['banned', 'installed_banned', /本主控安装已被授权方停用/],
    ['service_ticket_expired', 'installed_ticket_expired', /节点持有的授权签名凭据已过期/]]) {
    const result = run(status, 'pending')
    assert.equal(result.status, 3, result.stderr)
    assert.match(result.stdout, new RegExp(`install-state: ${state}$`, 'm'))
    assert.doesNotMatch(result.stdout, /installed_pending_initialization/)
    assert.match(result.stderr, text)
    assert.doesNotMatch(result.stderr, /TICK/)
    assert.match(result.stderr, /KEEP true/)
  }
})

// 未在本次注册为 pending（已初始化或 --resume）却等不到首票：说明“等待凭据生效”的排查，不再要求去初始化。
test('an initialized node still waiting for its ticket is told how to check the credential, not to initialize it', () => {
  const result = run('no_ticket', '')
  assert.equal(result.status, 3, result.stderr)
  assert.match(result.stdout, /install-state: installed_pending_ticket$/m)
  assert.match(result.stderr, /授权签名凭据仍未生效/)
  assert.match(result.stderr, /journalctl -u cdnca-edge-agent 中 installation ban/)
  assert.match(result.stderr, /若本机还在「节点列表 → 待初始化」中/)
})

test('register_node records node.admin_state from the registration response', () => {
  assert.match(block('register_node'), /REGISTERED_ADMIN_STATE=\$\(jq -r '\.node\.admin_state \| select\(type == "string" and test\("\^\[a-z_\]\{1,32\}\$"\)\)' "\$response"/)
  assert.match(source, /\nREGISTERED_ADMIN_STATE=''\nwait_first_ticket\(\) \{/)
})

test('the installer waits for the first ticket right after the service is stable and records done only when serving', () => {
  assert.match(source, /\n {2}setup_service\n {2}verify_agent_connected\n {2}wait_first_ticket\n {2}install_state_add step=done\n/)
  assert.match(source, /readonly INSTALLATION_BAN_STATE="\/var\/lib\/cdnca-edge-agent-backups\/active-state\/gateway-journal\/installation-ban\/state\.json"/)
})

// installer-hardening ih-node：待初始化退出 3 时打印完整的下一步清单（REINSTALL 2.3/2.4 的手工步骤），
// 续装命令不再要求重新取注册密钥，check 命令指向本机保存的安装器副本。
test('pending initialization prints the numbered next steps: initialize, line group, --resume without a key, check', () => {
  const result = run(null, 'pending')
  assert.equal(result.status, 3, result.stderr)
  assert.match(result.stderr, /下一步：\n\s+1\) .*初始化/)
  assert.match(result.stderr, /2\) .*线路组/)
  assert.match(result.stderr, /3\) （可选，只用于复核）.*--resume.*无需重新取注册密钥.*不执行也不影响节点开放/)
  assert.match(result.stderr, /4\) .*\/var\/lib\/cdnca-node-install\/install-node\.sh check/)
})

// fix-nodepending：真正的失败状态（停用、凭据过期、恢复失败、超时未拿到凭据）仍是 error 行，不设提示文案，
// 退出时照常标红色 ✗ 失败。
test('real failures keep the error line and set no expected-exit notice', () => {
  for (const [status, adminState, stopped] of [['banned', 'pending', false], ['service_ticket_expired', '', false],
    ['serving', 'pending', true], [null, '', false]]) {
    const result = run(status, adminState, stopped)
    assert.equal(result.status, 3, result.stderr)
    assert.match(result.stderr, /\[cdnca-edge\] error: /)
    assert.doesNotMatch(result.stderr, /NOTICE|待主控初始化/)
  }
})
