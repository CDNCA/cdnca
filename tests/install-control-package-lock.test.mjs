import assert from 'node:assert/strict'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
// 被抽取的函数会调用进度展示（未 progress_init 时原样直通），与函数一起加载。
const progress = readFileSync(new URL('../scripts/lib/install-progress.sh', import.meta.url), 'utf8')
// 内嵌的 scripts/lib/package-automation.sh（含 quiesce_package_automation）与随后的 cleanup。
const prelude = source.match(/^# >>> BEGIN package-automation [^\n]*\n[\s\S]*?^trap cleanup EXIT\n/m)?.[0]

// Runs the real timer pause/wait/restore logic against stubbed systemd: a fresh
// host where apt-daily.service is still running for the first `busyPolls` checks.
// 暂停并在退出时恢复是 --keep-unattended-upgrades 的语义；默认停用见 install-package-automation.test.mjs。
function run({ busyPolls = 0, systemd = true, timers = ['apt-daily.timer', 'apt-daily-upgrade.timer'] } = {}) {
  assert.ok(prelude, 'extract the real quiesce and cleanup functions')
  const root = mkdtempSync(join(tmpdir(), 'cdnca-apt-quiesce-'))
  const bin = join(root, 'bin'), runDir = join(root, 'run-systemd')
  mkdirSync(bin)
  if (systemd) mkdirSync(runDir)
  writeFileSync(join(root, 'polls'), '0')
  writeFileSync(join(bin, 'systemctl'), `#!/bin/bash
echo "$*" >> "${root}/systemctl.log"
if [ "$1" = is-active ]; then
  shift; [ "$1" = --quiet ] && shift
  case "$1" in
    *.timer) case " ${timers.join(' ')} " in *" $1 "*) exit 0 ;; esac; exit 3 ;;
    *.service) n=$(cat "${root}/polls"); echo $((n + 1)) > "${root}/polls"; [ "$n" -lt ${busyPolls} ] && exit 0; exit 3 ;;
  esac
fi
exit 0
`)
  writeFileSync(join(bin, 'pgrep'), '#!/bin/sh\nexit 1\n')
  writeFileSync(join(bin, 'sleep'), `#!/bin/sh\necho slept >> "${root}/sleep.log"\n`)
  for (const name of ['systemctl', 'pgrep', 'sleep']) chmodSync(join(bin, name), 0o755)
  const script = [
    'set -Eeuo pipefail', 'TEMP_DIR=$(mktemp -d)', progress,
    'log() { printf "LOG %s\\n" "$*"; }', 'fail() { printf "FAIL %s\\n" "$*"; exit 1; }',
    prelude.replaceAll('/run/systemd/system', runDir),
    'KEEP_UNATTENDED_UPGRADES=true', 'quiesce_package_automation', 'echo "QUIESCED ${#PAUSED_APT_TIMERS[@]}"',
  ].join('\n')
  const result = spawnSync('/bin/bash', ['-c', script], { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin` } })
  const read = (name) => (existsSync(join(root, name)) ? readFileSync(join(root, name), 'utf8') : '')
  const out = { ...result, calls: read('systemctl.log').trim().split('\n').filter(Boolean), sleeps: read('sleep.log').split('\n').filter(Boolean).length }
  rmSync(root, { recursive: true, force: true })
  return out
}

test('boot-time apt jobs are waited out and their timers paused, then restored on exit', () => {
  const result = run({ busyPolls: 2 })
  assert.equal(result.status, 0, result.stderr + result.stdout)
  assert.match(result.stdout, /QUIESCED 2/)
  assert.match(result.stdout, /waiting for the running automatic package update/)
  assert.equal(result.sleeps, 2)
  assert.ok(result.calls.includes('stop apt-daily.timer') && result.calls.includes('stop apt-daily-upgrade.timer'))
  assert.equal(result.calls.at(-1), 'start apt-daily.timer apt-daily-upgrade.timer')
})

test('timers the operator had disabled stay disabled', () => {
  const result = run({ timers: ['apt-daily.timer'] })
  assert.equal(result.status, 0, result.stderr)
  assert.ok(!result.calls.includes('stop apt-daily-upgrade.timer'))
  assert.equal(result.calls.at(-1), 'start apt-daily.timer')
})

test('hosts without systemd are left untouched', () => {
  const result = run({ systemd: false })
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(result.calls, [])
})

test('apt-get honours a dpkg lock timeout through APT_CONFIG', () => {
  assert.match(source, /^printf 'DPkg::Lock::Timeout "900";\\n' >"\$TEMP_DIR\/apt-lock.conf"\nexport APT_CONFIG="\$TEMP_DIR\/apt-lock.conf"$/m)
  const main = source.match(/^main\(\) \{[\s\S]*?^\}\n/m)?.[0] ?? ''
  assert.ok(main.indexOf('quiesce_package_automation') > -1 &&
    main.indexOf('quiesce_package_automation') < main.indexOf('install_dependencies'), 'quiesce before the first apt-get')
})
