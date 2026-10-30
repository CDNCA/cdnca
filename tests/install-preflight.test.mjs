import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'
import { embedded, installers } from '../scripts/sync-install-preflight.mjs'

// Shared installer preflight: simulated hosts via PREFLIGHT_ROOT (/etc, /proc,
// /sys) and fake uname/systemctl/df/id/curl/date commands on PATH.
const library = new URL('../scripts/lib/install-preflight.sh', import.meta.url).pathname
const repository = new URL('..', import.meta.url).pathname

const osRelease = {
  ubuntu2404: 'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n',
  ubuntu2204: 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n',
  ubuntu1604: 'ID=ubuntu\nVERSION_ID="16.04"\nPRETTY_NAME="Ubuntu 16.04.7 LTS"\n',
  ubuntu2004: 'ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n',
  ubuntu1804: 'ID=ubuntu\nVERSION_ID="18.04"\nPRETTY_NAME="Ubuntu 18.04.6 LTS"\n',
  debian9: 'ID=debian\nVERSION_ID="9"\nPRETTY_NAME="Debian GNU/Linux 9 (stretch)"\n',
  debian11: 'ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n',
  debian12: 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n',
  debian13: 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n',
  centos7: 'ID="centos"\nVERSION_ID="7"\nPRETTY_NAME="CentOS Linux 7 (Core)"\n',
  rocky8: 'ID="rocky"\nVERSION_ID="8.9"\nPRETTY_NAME="Rocky Linux 8.9 (Green Obsidian)"\n',
  rocky9: 'ID="rocky"\nVERSION_ID="9.3"\nPRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"\n',
  alma10: 'ID="almalinux"\nVERSION_ID="10.0"\nPRETTY_NAME="AlmaLinux 10.0"\n',
  rhel9: 'ID="rhel"\nVERSION_ID="9.4"\nPRETTY_NAME="Red Hat Enterprise Linux 9.4"\n',
  alpine: 'ID=alpine\nVERSION_ID=3.20.0\nPRETTY_NAME="Alpine Linux v3.20"\n',
}

// /proc/net/tcp row: local address 0.0.0.0:<port hex>, state 0A (LISTEN).
const tcpRows = (ports) => '  sl  local_address rem_address   st\n' + ports.map((port, index) =>
  `   ${index}: 00000000:${port.toString(16).toUpperCase().padStart(4, '0')} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1\n`).join('')

function host({ os = 'ubuntu2404', memMiB = 8192, swapMiB = 0, cores = 4, sse42 = true, kernel = '6.8.0-45-generic',
  machine = 'x86_64', systemd = '255', systemdRunning = true, cgroup2 = true, uid = 0, listen = [], availMiB = 200000,
  curl = 'ok', remoteDate = 'Wed, 15 Oct 2026 08:00:00 GMT', localEpoch = 1792051200, firewall = '' } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 'preflight-'))
  const bin = path.join(root, 'bin')
  for (const dir of ['etc', 'proc/net', 'sys/fs/cgroup', 'run/systemd/system', 'bin']) mkdirSync(path.join(root, dir), { recursive: true })
  if (!systemdRunning) rmSync(path.join(root, 'run/systemd/system'), { recursive: true })
  if (os) writeFileSync(path.join(root, 'etc/os-release'), osRelease[os])
  writeFileSync(path.join(root, 'proc/meminfo'), `MemTotal:       ${memMiB * 1024} kB\nSwapTotal:      ${swapMiB * 1024} kB\n`)
  writeFileSync(path.join(root, 'proc/cpuinfo'), Array.from({ length: cores }, (_, index) =>
    `processor\t: ${index}\nflags\t\t: fpu sse2 ${sse42 ? 'sse4_2 ' : ''}avx\n\n`).join(''))
  writeFileSync(path.join(root, 'proc/net/tcp'), tcpRows(listen))
  writeFileSync(path.join(root, 'proc/net/tcp6'), tcpRows([]))
  if (cgroup2) writeFileSync(path.join(root, 'sys/fs/cgroup/cgroup.controllers'), 'cpu memory\n')
  const fake = (name, body) => { writeFileSync(path.join(bin, name), `#!/usr/bin/env bash\n${body}\n`); chmodSync(path.join(bin, name), 0o755) }
  fake('uname', `case "$1" in -m) echo ${machine} ;; -r) echo ${kernel} ;; *) echo Linux ;; esac`)
  fake('systemctl', `[ "$1" = --version ] && echo "systemd ${systemd} (${systemd})"`)
  fake('df', `printf 'Filesystem 1048576-blocks Used Available Capacity Mounted on\\n/dev/vda1 300000 1000 ${availMiB} 1%% /\\n'`)
  fake('id', `case "$1" in -u) echo ${uid} ;; -un) echo tester ;; esac`)
  fake('date', `case "$*" in '-u +%s') echo ${localEpoch} ;; *) exec /bin/date "$@" ;; esac`)
  const curlBody = { ok: `printf 'HTTP/2 200\\r\\ndate: ${remoteDate}\\r\\n\\r\\n'`, untrusted: 'exit 60', down: 'exit 7' }[curl]
  fake('curl', curlBody)
  if (firewall === 'ufw') fake('ufw', "echo 'Status: active'")
  if (firewall === 'firewalld') fake('firewall-cmd', 'exit 0')
  return { root, bin }
}

// Runs preflight functions against a fixture; GNU date -d is replaced by a
// fixed parser so the test also runs where date is BSD.
function run(fixture, commands, { tty = false, yes = false } = {}) {
  const script = [
    'set -Eeuo pipefail',
    `source ${JSON.stringify(library)}`,
    `preflight_date_epoch() { case "$1" in 'Wed, 15 Oct 2026 08:00:00 GMT') echo 1792051200 ;; 'Wed, 15 Oct 2026 07:58:00 GMT') echo 1792051080 ;; 'Wed, 15 Oct 2026 07:50:00 GMT') echo 1792050600 ;; esac; }`,
    ...(tty ? [] : ['exec </dev/null']),
    commands,
  ].join('\n')
  const result = spawnSync('bash', ['-c', script], {
    encoding: 'utf8',
    env: { PATH: `${fixture.bin}:/usr/bin:/bin:/usr/sbin:/sbin`, PREFLIGHT_ROOT: fixture.root, PREFLIGHT_ASSUME_YES: String(yes), HOME: fixture.root },
  })
  rmSync(fixture.root, { recursive: true, force: true })
  return result
}

const statusOf = (result, item) => {
  const line = result.stderr.split('\n').find((row) => row.includes(`] ${item}：`))
  return line?.match(/\[(通过|警告|不通过)\]/)?.[1]
}
const report = (commands) => `${commands}\npreflight_report '[t]' || exit 9`

test('installers embed the shared preflight library verbatim', () => {
  const source = readFileSync(library, 'utf8')
  for (const relative of installers) {
    assert.equal(embedded(readFileSync(path.join(repository, relative), 'utf8')).body, source, `${relative} is stale; run node scripts/sync-install-preflight.mjs`)
  }
})

test('operating system tiers follow the support matrix for control and node', () => {
  const cases = [
    ['ubuntu2404', 'control', '通过'], ['ubuntu2404', 'node', '通过'],
    ['ubuntu2204', 'node', '警告'], ['debian12', 'node', '警告'], ['debian13', 'control', '警告'], ['debian13', 'node', '警告'],
    ['ubuntu2204', 'control', '警告'], ['debian12', 'control', '警告'],
    ['rocky9', 'node', '警告'], ['alma10', 'node', '警告'], ['rhel9', 'node', '警告'],
    ['rocky9', 'control', '警告'], ['alma10', 'control', '警告'], ['rhel9', 'control', '警告'],
    ['ubuntu1604', 'node', '不通过'], ['ubuntu2004', 'control', '警告'], ['debian9', 'node', '不通过'],
    ['debian11', 'control', '警告'], ['ubuntu1804', 'control', '不通过'], ['ubuntu1804', 'node', '警告'], ['centos7', 'node', '不通过'], ['rocky8', 'node', '警告'], ['rocky8', 'control', '警告'], ['alpine', 'node', '不通过'],
  ]
  for (const [os, role, expected] of cases) {
    const result = run(host({ os }), report(`preflight_check_os ${role}`))
    assert.equal(statusOf(result, '操作系统'), expected, `${os} ${role}: ${result.stderr}`)
  }
  const centos = run(host({ os: 'centos7' }), report('preflight_check_os node'))
  assert.match(centos.stderr, /CentOS 7 已停止维护/)
  assert.match(centos.stderr, /建议：请改用 Ubuntu 24.04/)
  const missing = run(host({ os: '' }), report('preflight_check_os node'))
  assert.equal(statusOf(missing, '操作系统'), '不通过')
})

test('architecture, SSE4.2 and node kernel/cgroup requirements', () => {
  assert.equal(statusOf(run(host({ machine: 'aarch64' }), report('preflight_check_arch node')), 'CPU架构'), '不通过')
  assert.equal(statusOf(run(host({ sse42: false }), report('preflight_check_arch control')), 'CPU架构'), '不通过')
  assert.equal(statusOf(run(host({ sse42: false }), report('preflight_check_arch node')), 'CPU架构'), '通过')
  assert.equal(statusOf(run(host({ kernel: '5.4.0-1-generic' }), report('preflight_check_kernel node')), '内核'), '警告')
  const v1 = run(host({ cgroup2: false }), report('preflight_check_kernel node'))
  assert.equal(statusOf(v1, '内核'), '通过')
  assert.equal(statusOf(v1, 'cgroup'), '警告')
  assert.equal(statusOf(run(host({ kernel: '5.14.0-427.el9.x86_64' }), report('preflight_check_kernel node')), '内核'), '通过')
  // Below 5.3 only a live pidfd_open probe decides (vendor backports exist).
  const old = (probe) => run(host({ kernel: '3.10.0-1160.el7.x86_64' }), report(`preflight_pidfd_probe() { return ${probe}; }\npreflight_check_kernel node`))
  assert.equal(statusOf(old(1), '内核'), '不通过')
  assert.match(old(1).stderr, /不支持 pidfd_open/)
  assert.match(old(1).stderr, /ELRepo kernel-lt/)
  assert.equal(statusOf(old(2), '内核'), '不通过')
  assert.equal(statusOf(old(0), '内核'), '警告')
  assert.equal(statusOf(run(host({ kernel: '5.4.0-1-generic', cgroup2: false }), report('preflight_check_kernel control')), '内核'), '通过')
})

test('memory, CPU and disk thresholds', () => {
  const memory = [
    // 推荐配置：主控 16G、节点 8G，低于推荐告警；最低（主控 4G、节点 1G+2G Swap）不变。
    ['control', 3000, 0, '不通过'], ['control', 3800, 0, '警告'], ['control', 7900, 0, '警告'], ['control', 15900, 0, '通过'],
    ['node', 800, 0, '不通过'], ['node', 950, 2048, '警告'], ['node', 800, 2048, '警告'], ['node', 1500, 0, '警告'], ['node', 1900, 0, '警告'],
    ['node', 7900, 0, '通过'],
  ]
  for (const [role, memMiB, swapMiB, expected] of memory) {
    const result = run(host({ memMiB, swapMiB }), report(`preflight_check_memory ${role}`))
    assert.equal(statusOf(result, '内存'), expected, `${role} ${memMiB}+${swapMiB}: ${result.stderr}`)
  }
  assert.equal(statusOf(run(host({ cores: 2 }), report('preflight_check_cpu control')), 'CPU核数'), '警告')
  assert.equal(statusOf(run(host({ cores: 2 }), report('preflight_check_cpu node')), 'CPU核数'), '警告')
  assert.equal(statusOf(run(host({ cores: 4 }), report('preflight_check_cpu control')), 'CPU核数'), '通过')
  assert.equal(statusOf(run(host({ cores: 4 }), report('preflight_check_cpu node')), 'CPU核数'), '通过')
  assert.equal(statusOf(run(host({ availMiB: 5000 }), report('preflight_check_disk control')), '磁盘空间'), '不通过')
  assert.equal(statusOf(run(host({ availMiB: 20000 }), report('preflight_check_disk control')), '磁盘空间'), '警告')
  assert.equal(statusOf(run(host({ availMiB: 1000 }), report('preflight_check_disk node')), '磁盘空间'), '不通过')
  // All paths share one mounted filesystem; it is reported once.
  const once = run(host({ availMiB: 50000 }), report('preflight_check_disk node'))
  assert.equal(once.stderr.split('\n').filter((line) => line.includes('磁盘空间')).length, 1, once.stderr)
})

test('systemd presence/version, root and coexistence', () => {
  assert.equal(statusOf(run(host({ systemdRunning: false }), report('preflight_check_os node; preflight_check_systemd')), 'systemd'), '不通过')
  assert.equal(statusOf(run(host({ os: 'ubuntu2204', systemd: '245' }), report('preflight_check_os node; preflight_check_systemd')), 'systemd'), '警告')
  assert.equal(statusOf(run(host({ os: 'ubuntu2204', systemd: '218' }), report('preflight_check_os node; preflight_check_systemd')), 'systemd'), '不通过')
  // Probes the host's systemd tables through the embedded systemd-compat library.
  const degraded = run(host({ os: 'ubuntu2204', systemd: '239' }), report(
    `systemd_compat_knows() { case "$1" in Service.ProtectClock|Service.ProtectHostname|@setuid) return 1 ;; esac; return 0; }\npreflight_check_os node; preflight_check_systemd`))
  assert.equal(statusOf(degraded, 'systemd'), '警告')
  assert.match(degraded.stderr, /沙箱加固降级，不支持: ProtectClock ProtectHostname；系统调用过滤分组缺失: @setuid/)
  assert.equal(statusOf(run(host({ os: 'ubuntu2204', systemd: '249' }), report('preflight_check_os node; preflight_check_systemd')), 'systemd'), '通过')
  assert.equal(statusOf(run(host({ uid: 1000 }), report('preflight_check_root')), 'root权限'), '不通过')
  const fixture = host()
  mkdirSync(path.join(fixture.root, 'etc/cdnca-control'))
  assert.equal(statusOf(run(fixture, report('preflight_check_coexistence node')), '主控共存'), '不通过')
})

test('listening ports are read from /proc/net/tcp', () => {
  const busy = run(host({ listen: [22, 443, 19443] }), report('preflight_check_ports 80:网站HTTP 443:网站HTTPS 19443:节点注册'))
  assert.equal(statusOf(busy, '端口占用'), '不通过')
  assert.match(busy.stderr, /443（网站HTTPS）、19443（节点注册）/)
  assert.doesNotMatch(busy.stderr, /80（/)
  assert.equal(statusOf(run(host({ listen: [22] }), report('preflight_check_ports 80:a 443:b')), '端口占用'), '通过')
})

test('connectivity and clock skew against the licensing server', () => {
  const ok = run(host(), report('preflight_check_remote 授权端 https://auth.example/'))
  assert.equal(statusOf(ok, '连通性（授权端）'), '通过')
  assert.equal(statusOf(ok, '时间偏差'), '通过')
  assert.equal(statusOf(run(host({ remoteDate: 'Wed, 15 Oct 2026 07:58:00 GMT' }), report('preflight_check_remote 授权端 https://a/')), '时间偏差'), '警告')
  const skewed = run(host({ remoteDate: 'Wed, 15 Oct 2026 07:50:00 GMT' }), report('preflight_check_remote 授权端 https://a/'))
  assert.equal(statusOf(skewed, '时间偏差'), '不通过')
  assert.match(skewed.stderr, /相差 600 秒/)
  assert.equal(statusOf(run(host({ curl: 'down' }), report('preflight_check_remote 授权端 https://a/ https://b/')), '连通性（授权端）'), '不通过')
  const untrusted = run(host({ curl: 'untrusted' }), report('preflight_check_remote 主控 https://10.0.0.1/'))
  assert.equal(statusOf(untrusted, '连通性（主控）'), '通过')
  assert.equal(statusOf(untrusted, '时间偏差'), '警告')
})

test('commands and firewall hints', () => {
  const missing = run(host(), report('preflight_check_commands bash definitely-missing-tool -- another-missing-tool'))
  assert.equal(statusOf(missing, '必需命令'), '不通过')
  assert.match(missing.stderr, /缺少: definitely-missing-tool/)
  const auto = run(host(), report('preflight_check_commands bash -- another-missing-tool'))
  assert.equal(statusOf(auto, '必需命令'), '通过')
  assert.match(auto.stderr, /将自动安装: another-missing-tool/)
  const either = run(host(), report('preflight_check_commands bash "missing-a|bash" "missing-b|missing-c"'))
  assert.match(either.stderr, /缺少: missing-b 或 missing-c/)
  assert.doesNotMatch(either.stderr, /missing-a/)
  const ufw = run(host({ firewall: 'ufw' }), report('preflight_check_firewall 443 19443'))
  assert.equal(statusOf(ufw, '防火墙'), '警告')
  assert.match(ufw.stderr, /ufw allow 443\/tcp; ufw allow 19443\/tcp;/)
  assert.match(run(host({ firewall: 'firewalld' }), report('preflight_check_firewall 80')).stderr, /firewall-cmd --permanent --add-port=80\/tcp; firewall-cmd --reload/)
})

test('report: failures stop, warnings continue non-interactively or with --yes', () => {
  const failed = run(host({ uid: 1000 }), report('preflight_check_root'))
  assert.equal(failed.status, 9)
  assert.match(failed.stderr, /1 项不通过/)
  assert.match(failed.stderr, /本机未做任何修改/)
  const warned = run(host({ cores: 1 }), report('preflight_check_cpu control'))
  assert.equal(warned.status, 0)
  assert.match(warned.stderr, /非交互运行，继续安装（加 --yes 可省略本提示）/)
  const yes = run(host({ cores: 1 }), report('preflight_check_cpu control'), { yes: true })
  assert.equal(yes.status, 0)
  assert.match(yes.stderr, /已指定 --yes，继续安装/)
  const clean = run(host(), report('preflight_check_root; preflight_check_cpu control'))
  assert.equal(clean.status, 0)
  assert.match(clean.stderr, /全部通过/)
})

test('a fully supported Ubuntu 24.04 control host passes every local check', () => {
  const result = run(host({ memMiB: 16384 }), report([
    'preflight_check_root', 'preflight_check_os control', 'preflight_check_arch control', 'preflight_check_kernel control',
    'preflight_check_cpu control', 'preflight_check_memory control', 'preflight_check_disk control', 'preflight_check_systemd',
    'preflight_check_coexistence control', 'preflight_check_ports 443:a 80:b', 'preflight_check_remote 授权端 https://a/',
    'preflight_check_selinux', 'preflight_check_firewall 443',
  ].join('\n')))
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stderr, /全部通过/)
})

test('signed control helpers accept exactly the hosts the preflight admits for control', () => {
  const admitted = [['ubuntu', '24.04'], ['ubuntu', '22.04'], ['ubuntu', '20.04'], ['debian', '10'], ['debian', '11'], ['debian', '12'], ['debian', '13'],
    ...['rocky', 'almalinux', 'rhel'].flatMap((id) => [[id, '8'], [id, '9'], [id, '10']])]
  for (const [id, version] of [...admitted, ['ubuntu', '18.04'], ['ubuntu', '16.04'], ['debian', '9'], ['centos', '7']]) {
    const tier = run(host(), `preflight_os_tier control ${id} ${version}`).stdout.trim()
    const expected = admitted.some(([i, v]) => i === id && v === version)
    assert.equal(tier === 'official' || tier === 'compatible', expected, `${id} ${version}: ${tier}`)
  }
  const pairs = (text) => [...text.matchAll(/\("([a-z]+)", "([0-9.]+)"\)/g)].map((match) => `${match[1]}:${match[2]}`).sort()
  const want = admitted.map(([i, v]) => `${i}:${v}`).sort()
  for (const relative of ['scripts/native-runtime/install-rustfs.py', 'scripts/native-runtime/install-native-baseline.py',
    'scripts/native-runtime/configure-native-upgrade.py', 'deploy/systemd/install-native-control-upgrade-runner.sh']) {
    assert.deepEqual(pairs(readFileSync(path.join(repository, relative), 'utf8')), want, relative)
  }
  const dependencies = readFileSync(path.join(repository, 'scripts/native-runtime/install-ubuntu-dependencies.sh'), 'utf8')
  for (const [id, version] of admitted.filter(([id]) => id === 'ubuntu' || id === 'debian')) {
    assert.ok(dependencies.includes(`ID=${id}\\nVERSION_CODENAME=`) && dependencies.includes(`VERSION_ID=${version}')`), `${id} ${version}`)
  }
  assert.ok(dependencies.includes("^ID=(rocky|almalinux|rhel)\\nVERSION_ID=(8|9|10)"), 'EL 8/9/10 profile')
})

test('installers accept --yes and run preflight before any mutation', () => {
  for (const [relative, first] of [['scripts/install-control.sh', 'prompt_public_endpoints'], ['scripts/install-node.sh', 'load_console_defaults']]) {
    const text = readFileSync(path.join(repository, relative), 'utf8')
    assert.match(text, /-y\|--yes\) ASSUME_YES=true; shift ;;/)
    const main = text.slice(text.indexOf('\nmain() {'))
    assert.ok(main.indexOf('  run_preflight\n') > 0 && main.indexOf('  run_preflight\n') < main.indexOf(`  ${first}\n`), relative)
  }
})
