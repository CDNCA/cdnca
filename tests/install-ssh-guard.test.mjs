import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, chmodSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'
import { embedded, embeds } from '../scripts/sync-install-preflight.mjs'

// C13（FINAL，"SSH 防爆破只装 fail2ban"）：六类安装器都装 fail2ban sshd，ignoreip 可配，不写死地址。
const repository = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const library = path.join(repository, 'scripts/lib/ssh-guard.sh')
const installers = ['install-control', 'install-node', 'install-auth', 'install-market', 'install-site']

function run(env, body = 'ssh_guard_setup') {
  const root = mkdtempSync(path.join(tmpdir(), 'ssh-guard-'))
  const bin = path.join(root, 'bin'); mkdirSync(bin)
  const calls = path.join(root, 'calls')
  for (const [name, script] of Object.entries({
    'fail2ban-client': `echo "fail2ban-client $*" >>${calls}`,
    systemctl: `echo "systemctl $*" >>${calls}`,
    'apt-get': `echo "apt-get $*" >>${calls}`,
  })) { writeFileSync(path.join(bin, name), `#!/bin/sh\n${script}\n`); chmodSync(path.join(bin, name), 0o755) }
  const result = spawnSync('bash', ['-c', `set -Eeuo pipefail; source ${JSON.stringify(library)}; ${body}`], { encoding: 'utf8',
    env: { PATH: `${bin}:/usr/bin:/bin`, SSH_GUARD_ROOT: root, ...env } })
  const jail = path.join(root, 'etc/fail2ban/jail.d/cdnca-sshd.local')
  return { result, jail: existsSync(jail) ? readFileSync(jail, 'utf8') : null, calls: existsSync(calls) ? readFileSync(calls, 'utf8') : '' }
}

test('the sshd jail is written with loopback plus the configured ignoreip and fail2ban is restarted', () => {
  const { result, jail, calls } = run({ SSH_GUARD_IGNOREIP: '198.51.100.7,203.0.113.0/24 2001:db8::/32' })
  assert.equal(result.status, 0, result.stderr)
  assert.match(jail, /^ignoreip = 127\.0\.0\.1\/8 ::1 198\.51\.100\.7 203\.0\.113\.0\/24 2001:db8::\/32$/m)
  assert.match(jail, /^\[sshd\]\nenabled = true\nport = ssh\nbackend = systemd$/m)
  assert.match(jail, /^maxretry = 5$/m)
  assert.match(calls, /fail2ban-client -t/)
  assert.match(calls, /systemctl restart fail2ban/)
})

test('no ignoreip keeps only loopback and warns; --no-ssh-guard writes nothing', () => {
  const plain = run({})
  assert.equal(plain.result.status, 0, plain.result.stderr)
  assert.match(plain.jail, /^ignoreip = 127\.0\.0\.1\/8 ::1$/m)
  assert.match(plain.result.stderr, /未给 --ssh-guard-ignoreip/)
  const off = run({ SSH_GUARD_ENABLED: 'false' })
  assert.equal(off.result.status, 0, off.result.stderr)
  assert.equal(off.jail, null)
  assert.equal(off.calls, '')
})

test('an invalid ignoreip entry is refused', () => {
  for (const value of ['example.com', '10.0.0.0/33', '1.2.3.4;reboot', '0.0.0.0/0 x']) {
    const { result, jail } = run({ SSH_GUARD_IGNOREIP: value })
    assert.notEqual(result.status, 0, value)
    assert.equal(jail, null)
  }
})

test('the guard library has no real addresses and every installer embeds it verbatim and wires the flags', () => {
  const source = readFileSync(library, 'utf8')
  assert.doesNotMatch(source.replace(/127\.0\.0\.1\/8/g, ''), /\b\d{1,3}(\.\d{1,3}){3}\b/)
  for (const name of installers) {
    const text = readFileSync(path.join(repository, `scripts/${name}.sh`), 'utf8')
    assert.ok(embeds[`scripts/${name}.sh`].includes('ssh-guard'), `${name} not in sync list`)
    assert.equal(embedded(text, 'ssh-guard').body, source, `${name} is stale; run node scripts/sync-install-preflight.mjs`)
    assert.match(text, /--ssh-guard-ignoreip\) [^\n]*SSH_GUARD_IGNOREIP=(\$2|\$\{2:\?)/, `${name} lacks --ssh-guard-ignoreip`)
    assert.match(text, /--no-ssh-guard\) SSH_GUARD_ENABLED=false/, `${name} lacks --no-ssh-guard`)
    assert.match(text, /\n {2}ssh_guard_setup\n/, `${name} does not call ssh_guard_setup`)
  }
})
