// 安装进度展示库 scripts/lib/install-progress.sh：剩余时间计算、非终端退化、NO_COLOR、
// 失败提示、apt/curl 输出折叠，以及两个安装器的阶段表与 main 里的 progress_stage 一一对应。
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { embedded } from '../scripts/sync-install-preflight.mjs'

const library = readFileSync(new URL('../scripts/lib/install-progress.sh', import.meta.url), 'utf8')
const installers = ['install-control.sh', 'install-node.sh'].map((name) => [name, readFileSync(new URL(`../scripts/${name}`, import.meta.url), 'utf8')])

// SECONDS 可写：fake_elapsed N 让后续计时从 N 秒开始，测试不用真等。
function run(body, { env = {}, stages = ["'甲|60|120|'", "'乙|60|120|'", "'丙|60|120|'"], tty = false } = {}) {
  const logDir = mkdtempSync(join(tmpdir(), 'cdnca-progress-'))
  const script = ['set -Eeuo pipefail', `PROGRESS_LABEL='[t]'`, 'PROGRESS_ROLE=test', `PROGRESS_STAGES=(${stages.join(' ')})`, library,
    // 测试里没有终端：用 [ 的包装模拟 “stderr 是终端”。
    tty ? '[() { if [[ "$1" == -t && "$2" == 2 ]]; then return 0; fi; builtin [ "$@"; }' : '',
    'fake_elapsed() { SECONDS=$1; }', body].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH, PROGRESS_LOG_DIR: logDir, TERM: 'xterm', ...env } })
  const logs = readdirSync(logDir)
  const log = logs.length ? readFileSync(join(logDir, logs[0]), 'utf8') : ''
  rmSync(logDir, { recursive: true, force: true })
  return { ...result, logs, log }
}

test('stage headers show index, interval, bar, elapsed and remaining from the stage weights', () => {
  const result = run('progress_init; progress_stage; fake_elapsed 90; progress_stage; progress_stage; progress_done')
  assert.equal(result.status, 0, result.stderr)
  const lines = result.stderr.split('\n')
  assert.match(lines[0], /^\[t\] 共 3 个步骤，预计约 3–6 分钟；完整输出写入 .*cdnca-install-test-\d{8}-\d{6}\.log$/)
  assert.equal(lines[1], '[t] [1/3] 甲（约 1–2 分钟）……')
  assert.match(lines[2], /^\[t\] \[-{24}\]   0%  已用 0:0\d  预计剩余约 3–6 分钟$/)
  assert.equal(lines[3], '[t] ✓ [1/3] 甲 完成（用时 1:30）')
  // 90 秒正好等于甲的权重中值，剩余不放大。
  assert.match(lines[5], /^\[t\] \[#{7}-{17}\]  33%  已用 1:3\d  预计剩余约 2–4 分钟$/)
  assert.match(result.stderr, /\[#{24}\] 100%  全部 3 个步骤完成，总用时 1:3\d。安装日志：/)
  assert.equal(result.logs.length, 1)
  assert.match(result.log, /\[2\/3\] 乙/)
})

test('remaining time is scaled up when completed stages ran slower than their weights', () => {
  // 甲中值 90 秒，实际 270 秒（3 倍）：乙+丙 2–4 分钟放大为 6–12 分钟。
  const result = run('progress_init; progress_stage; fake_elapsed 270; progress_stage')
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /33%  已用 4:3\d  预计剩余约 6–12 分钟/)
})

test('interactive stages do not calibrate the remaining time', () => {
  const result = run('progress_init; progress_stage; fake_elapsed 900; progress_stage', { stages: ["'输入|10|60|interactive'", "'乙|60|120|'"] })
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /预计剩余约 1–2 分钟/)
})

test('intervals are rounded and short spans stay in seconds', () => {
  const result = run('for pair in "0 15" "5 5" "20 180" "180 600" "0 90"; do set -- $pair; progress_span "$1" "$2"; echo; done')
  assert.equal(result.stdout, '约 0–15 秒\n约 5 秒\n约 1–3 分钟\n约 3–10 分钟\n约 2 分钟内\n')
})

test('a non-terminal gets no carriage returns or colours; a terminal gets colour unless NO_COLOR', () => {
  const body = 'progress_init; progress_stage; progress_run 安装 sh -c "sleep 2; echo raw-apt-line"; progress_done'
  const pipe = run(body)
  assert.equal(pipe.status, 0, pipe.stderr)
  assert.doesNotMatch(pipe.stderr, /[\r\x1b]/)
  assert.doesNotMatch(pipe.stderr, /raw-apt-line/, 'raw command output stays in the log')
  assert.match(pipe.log, />>> 安装\nraw-apt-line/)
  const terminal = run(body, { tty: true })
  assert.match(terminal.stderr, /\x1b\[32m✓ \[1\/3\] 甲 完成/)
  assert.match(terminal.stderr, /\r\x1b\[K\[t\]   仍在安装……已用 0:0\d/)
  const plain = run(body, { tty: true, env: { NO_COLOR: '1' } })
  assert.doesNotMatch(plain.stderr, /\x1b\[3[12]m|\x1b\[1m/)
  assert.match(plain.stderr, /\r/, 'NO_COLOR keeps the single-line refresh')
  const dumb = run(body, { tty: true, env: { TERM: 'dumb' } })
  assert.doesNotMatch(dumb.stderr, /[\r\x1b]/)
})

test('a failing long step reports its tail, exit code, stage and log; the status is preserved', () => {
  const result = run('trap \'progress_on_exit $?\' EXIT; progress_init; progress_stage; progress_stage; progress_run 安装依赖 sh -c "echo E: Unable to locate package x; exit 100"')
  assert.equal(result.status, 100)
  assert.match(result.stderr, /安装依赖失败（退出码 100），输出最后 30 行：\n {4}E: Unable to locate package x\n\[t\] ✗/)
  assert.match(result.stderr, /✗ \[2\/3\] 乙 失败（本步骤已用 0:0\d，退出码 100）。原因与处理办法见上方 error 行；完整输出：.*cdnca-install-test-/)
})

test('a non-terminal heartbeat appears every 15 seconds with the apt package counter', () => {
  const apt = ['0 upgraded, 3 newly installed, 0 to remove and 0 not upgraded.', 'Unpacking libpq5 (17.2-1) ...', 'Setting up libpq5 (17.2-1) ...',
    'Unpacking postgresql-17 (17.2-1) ...'].map((line) => `echo '${line}'`).join('; ')
  const result = run(`progress_init; progress_stage; progress_run 安装依赖 bash -c "${apt}; sleep 16"`)
  assert.equal(result.status, 0, result.stderr)
  const beats = result.stderr.split('\n').filter((line) => line.includes('仍在安装依赖'))
  assert.equal(beats.length, 1, result.stderr)
  assert.match(beats[0], /^\[t\]   仍在安装依赖……已用 0:1[5-6]  正在安装 1\/3：postgresql-17$/)
})

test('polling ticks print one line per 10 seconds with the timeout when not on a terminal', () => {
  const result = run('progress_init; progress_stage; for i in $(seq 0 25); do fake_elapsed $((100 + i)); progress_tick " Redis 就绪" 30; done')
  const ticks = result.stderr.split('\n').filter((line) => line.includes('等待'))
  assert.deepEqual(ticks, ['[t]   等待 Redis 就绪……已等 0:10，最长 0:30', '[t]   等待 Redis 就绪……已等 0:20，最长 0:30'])
})

test('curl progress meter folds to one line per 10% off a terminal and keeps curl errors', () => {
  const meter = ['  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current',
    '                                 Dload  Upload   Total   Spent    Left  Speed',
    ...[0, 4, 12, 15, 37, 61, 99, 100].map((pct) => `${String(pct).padStart(3)}  237M  ${String(pct).padStart(3)} ${Math.round(237 * pct / 100)}M    0     0  5000k      0  0:00:48  0:00:10  0:00:38 5120k`)]
  const fakeCurl = `fake_curl() { printf '%s\\r' ${meter.map((line) => JSON.stringify(line)).join(' ')} >&2; printf 'curl: (18) transfer closed\\n' >&2; echo body; }`
  const result = run(`${fakeCurl}\nprogress_init; progress_download 依赖包 fake_curl`)
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'body\n', 'curl stdout is untouched')
  const lines = result.stderr.split('\n').filter((line) => line.includes('下载 依赖包'))
  assert.deepEqual(lines.map((line) => line.match(/：(\d+)%/)[1]), ['0', '12', '37', '61', '99', '100'])
  assert.match(lines[1], /^\[t\]   下载 依赖包：12%（28M\/237M，5120k\/s）$/)
  assert.match(result.stderr, /curl: \(18\) transfer closed/)
  assert.doesNotMatch(result.stderr, /Dload|% Total|\r/)
})

test('without progress_init every helper is a transparent pass-through', () => {
  const result = run('progress_stage; progress_tick x 5; progress_done; progress_run x sh -c "echo out; echo err >&2"; progress_download x sh -c "echo dl"; PROGRESS_RUN_OUTPUT=$(mktemp) progress_run x sh -c "echo saved"')
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'out\ndl\n')
  assert.equal(result.stderr, 'err\n')
  assert.equal(result.logs.length, 0)
})

for (const [name, source] of installers) {
  test(`${name} embeds the library verbatim and has one progress_stage per stage`, () => {
    assert.equal(embedded(source, 'install-progress').body, library, `${name} is stale; run node scripts/sync-install-preflight.mjs`)
    const stages = source.match(/^PROGRESS_STAGES=\(\n([\s\S]*?)\n\)$/m)[1].split('\n')
    for (const stage of stages) assert.match(stage, /^ {2}'[^|']+\|\d+\|\d+\|(interactive)?'$/)
    const main = source.match(/^main\(\) \{[\s\S]*?^\}$/m)[0]
    assert.equal(main.split('\n').filter((line) => line.trim() === 'progress_stage').length, stages.length)
    assert.ok(main.indexOf('progress_init') < main.indexOf('progress_stage'))
    assert.match(main, /progress_done\n\}$/)
    assert.match(source, /^cleanup\(\) \{\n {2}local status=\$\?.*\n {2}\[ -z "\$\{PROGRESS_PREFIX:-\}" \] \|\| progress_on_exit "\$status"$/m)
  })
}
