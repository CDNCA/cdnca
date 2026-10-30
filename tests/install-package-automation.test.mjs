// AUDIT-1029 ①-11：主控与节点安装器默认停用 apt-daily/apt-daily-upgrade/unattended-upgrades，
// --keep-unattended-upgrades 保留系统默认（只在安装期间暂停定时器）。从两个生产脚本抽取真实函数，
// 用打桩的 systemctl 运行；不碰宿主 systemd。
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8')
const library = read('../scripts/lib/package-automation.sh')
const progress = read('../scripts/lib/install-progress.sh')
const installers = { control: read('../scripts/install-control.sh'), node: read('../scripts/install-node.sh') }
const block = (source, name) => source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}\\n`, 'm'))?.[0]

// units：单元名 -> { enabled, active }；busyPolls：apt-daily.service 前几次查询仍在运行。
function run(installer, { args = [], units, busyPolls = 0 } = {}) {
  const source = installers[installer]
  const root = mkdtempSync(join(tmpdir(), 'cdnca-apt-automation-'))
  const bin = join(root, 'bin'), runDir = join(root, 'run-systemd')
  mkdirSync(bin)
  mkdirSync(runDir)
  writeFileSync(join(root, 'polls'), '0')
  const enabled = Object.keys(units).filter((name) => units[name].enabled).join(' ')
  const active = Object.keys(units).filter((name) => units[name].active).join(' ')
  writeFileSync(join(bin, 'systemctl'), `#!/bin/bash
echo "$*" >> "${root}/systemctl.log"
verb=$1; shift; [ "\${1:-}" = --quiet ] && shift
case "$verb" in
  is-enabled) case " ${enabled} " in *" $1 "*) exit 0 ;; esac; exit 1 ;;
  is-active)
    case "$1" in apt-daily.service)
      n=$(cat "${root}/polls"); echo $((n + 1)) > "${root}/polls"; [ "$n" -lt ${busyPolls} ] && exit 0; exit 3 ;; esac
    case " ${active} " in *" $1 "*) exit 0 ;; esac; exit 3 ;;
esac
exit 0
`)
  writeFileSync(join(bin, 'pgrep'), '#!/bin/sh\nexit 1\n')
  writeFileSync(join(bin, 'sleep'), '#!/bin/sh\n:\n')
  for (const name of ['systemctl', 'pgrep', 'sleep']) chmodSync(join(bin, name), 0o755)
  const begin = '# >>> BEGIN package-automation (generated from scripts/lib/package-automation.sh; do not edit here)\n'
  assert.ok(source.includes(begin + library), `${installer} must embed scripts/lib/package-automation.sh verbatim`)
  const parse = block(source, 'parse_args')
  assert.ok(parse, 'parse_args')
  const script = [
    'set -Eeuo pipefail', 'TEMP_DIR=$(mktemp -d)', progress,
    'log() { printf "LOG %s\\n" "$*"; }', 'fail() { printf "FAIL %s\\n" "$*"; exit 1; }', 'usage() { :; }',
    library.replaceAll('/run/systemd/system', runDir), parse,
    'parse_args "$@"', 'quiesce_package_automation',
    'echo "PAUSED ${PAUSED_APT_TIMERS[*]:-}"',
  ].join('\n')
  const result = spawnSync('/bin/bash', ['-c', script, 'test', ...args], { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin` } })
  const calls = existsSync(join(root, 'systemctl.log')) ? readFileSync(join(root, 'systemctl.log'), 'utf8').trim().split('\n') : []
  rmSync(root, { recursive: true, force: true })
  return { ...result, calls }
}

const ubuntu = () => ({
  'apt-daily.timer': { enabled: true, active: true },
  'apt-daily-upgrade.timer': { enabled: true, active: true },
  'unattended-upgrades.service': { enabled: true, active: true },
})

for (const installer of ['control', 'node']) {
  test(`${installer}: production default disables the three automatic update units after the running job ends`, () => {
    const result = run(installer, { units: ubuntu(), busyPolls: 2 })
    assert.equal(result.status, 0, result.stderr + result.stdout)
    const disables = result.calls.filter((call) => call.startsWith('disable'))
    assert.deepEqual(disables, ['disable --now apt-daily.timer', 'disable --now apt-daily-upgrade.timer',
      'disable --now unattended-upgrades.service'])
    // 先等正在跑的自动更新结束，再停用。
    assert.ok(result.calls.lastIndexOf('is-active --quiet apt-daily.service apt-daily-upgrade.service') <
      result.calls.indexOf('disable --now apt-daily.timer'))
    assert.match(result.stderr, /已停用系统自动更新（apt-daily\.timer apt-daily-upgrade\.timer unattended-upgrades\.service）/)
    assert.match(result.stderr, /可手动 apt-get update && apt-get upgrade/)
    assert.match(result.stderr, /systemctl enable --now apt-daily\.timer apt-daily-upgrade\.timer unattended-upgrades\.service/)
    // 停用后的定时器在退出时不得被 cleanup 重新启动。
    assert.match(result.stdout, /^PAUSED $/m)
  })

  test(`${installer}: --keep-unattended-upgrades only pauses the timers for the install`, () => {
    const result = run(installer, { args: ['--keep-unattended-upgrades'], units: ubuntu() })
    assert.equal(result.status, 0, result.stderr + result.stdout)
    assert.equal(result.calls.filter((call) => call.startsWith('disable')).length, 0)
    assert.match(result.stdout, /^PAUSED apt-daily\.timer apt-daily-upgrade\.timer$/m)
    assert.match(result.stderr, /已按 --keep-unattended-upgrades 保留系统自动更新/)
  })

  test(`${installer}: units that are absent or already disabled are left alone`, () => {
    const result = run(installer, { units: { 'apt-daily.timer': { enabled: true, active: false } } })
    assert.equal(result.status, 0, result.stderr + result.stdout)
    assert.deepEqual(result.calls.filter((call) => call.startsWith('disable')), ['disable --now apt-daily.timer'])
  })

  test(`${installer}: quiesce runs before the first package manager call and the option is documented`, () => {
    const source = installers[installer]
    const main = block(source, 'main') ?? ''
    const quiesce = main.indexOf('quiesce_package_automation')
    assert.ok(quiesce > -1, 'main must call quiesce_package_automation')
    assert.ok(quiesce < main.indexOf('install_dependencies'), 'quiesce before install_dependencies')
    assert.match(block(source, 'usage') ?? '', /--keep-unattended-upgrades/)
    assert.match(block(source, 'cleanup') ?? '', /PAUSED_APT_TIMERS/)
  })
}
