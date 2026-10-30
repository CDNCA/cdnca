// X15：主控/节点安装失败后，提示里给出的诊断位置在安装器退出（清理临时目录）后必须仍然存在。
// 从生产脚本抽取真实函数，用本地退出 47 的 control-api 替身触发失败分支；不联网、不碰数据库或服务。
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const control = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const progress = readFileSync(new URL('../scripts/lib/install-progress.sh', import.meta.url), 'utf8')
function block(source, name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function runBranch(step, { logDir }) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-install-diagnostics-'))
  const temp = join(root, 'install-temp')
  mkdirSync(temp)
  mkdirSync(join(root, 'log'))
  const binary = join(root, 'control-api')
  writeFileSync(binary, '#!/bin/sh\necho "stand-in failure for $1: relation \\"platform_users\\" does not exist" >&2\nexit 47\n')
  chmodSync(binary, 0o755)
  const script = ['set -Eeuo pipefail', control.match(/^log\(\) .*$/m)[0], control.match(/^fail\(\) .*$/m)[0],
    "PROGRESS_LABEL='[cdnca-control]'", 'PROGRESS_ROLE=control',
    "PROGRESS_STAGES=('初始化管理端数据|20|120|')", progress, 'PAUSED_APT_TIMERS=()', 'control_install_failed_hint() { :; }',
    'prompt_admin_password() { ADMIN_PASSWORD=secret-password; }',
    block(control, 'cleanup'), 'trap cleanup EXIT', block(control, step),
    'progress_init', 'PROGRESS_VERSION=1.0.35', 'progress_stage', step].join('\n')
  const result = spawnSync('bash', ['-c', script], {
    encoding: 'utf8', env: { PATH: process.env.PATH, PROGRESS_LOG_DIR: logDir ?? join(root, 'log'), TEMP_DIR: temp,
      CONTROL_BINARY: binary, DATABASE_URL: 'postgresql://localhost/test', ADMIN_USERNAME: 'admin', ADMIN_EMAIL: 'a@example.com',
      PKI_DIR: root, NO_COLOR: '1' },
  })
  return { root, temp, result }
}

for (const [step, label] of [['bootstrap_admin', 'control-api bootstrap-user'],
  ['bootstrap_node_ca', 'control-api bootstrap-node-ca'],
  ['bootstrap_system_configuration', 'control-api bootstrap-system-configuration']]) {
  test(`${step} failure keeps its output in the install log after cleanup`, () => {
    const { root, temp, result } = runBranch(step, {})
    try {
      assert.equal(result.status, 1, result.stderr)
      assert.equal(existsSync(temp), false, 'temporary directory with secrets must still be removed')
      const match = result.stderr.match(/inspect '>>> ([^']+)' in (\S+) before retrying/)
      assert.ok(match, result.stderr)
      assert.equal(match[1], label)
      const log = match[2]
      assert.ok(existsSync(log), `${log} must exist after exit`)
      assert.equal(statSync(log).mode & 0o777, 0o600)
      const content = readFileSync(log, 'utf8')
      assert.match(content, new RegExp(`>>> ${label}（失败输出）`))
      assert.match(content, /stand-in failure for bootstrap/)
      assert.match(content, /初始化管理端数据 失败（版本 1\.0\.35，/)
      assert.match(result.stderr, /退出码 1/)
      assert.doesNotMatch(content, /secret-password/)
    } finally { rmSync(root, { recursive: true, force: true }) }
  })
}

test('when the install log cannot be written the failure output goes to stderr and no path is promised', () => {
  const { root, temp, result } = runBranch('bootstrap_system_configuration', { logDir: '/nonexistent/cdnca-log-dir' })
  try {
    assert.equal(result.status, 1)
    assert.equal(existsSync(temp), false)
    assert.match(result.stderr, /stand-in failure for bootstrap-system-configuration/)
    assert.match(result.stderr, /system configuration bootstrap failed; its output is printed above/)
    assert.doesNotMatch(result.stderr, /inspect /)
    assert.deepEqual(readdirSync(root).filter((name) => name.endsWith('.log')), [])
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('no failure message points into the temporary directory that cleanup removes', () => {
  for (const file of ['../scripts/install-control.sh', '../scripts/install-node.sh']) {
    const source = readFileSync(new URL(file, import.meta.url), 'utf8')
    assert.doesNotMatch(source, /(fail|warn) [^\n]*inspect \$\{?TEMP_DIR/, file)
  }
})
