import assert from 'node:assert/strict'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { test } from 'node:test'
import { embedded, embeds } from '../scripts/sync-install-preflight.mjs'

const repository = new URL('..', import.meta.url).pathname
const library = join(repository, 'scripts/lib/systemd-compat.sh')

// Directives by first upstream systemd release, enough to model each target.
const since = {
  'Unit.StartLimitIntervalSec': 230, 'Unit.StartLimitBurst': 230, 'Service.Type': 1, 'Service.ExecStart': 1, 'Service.User': 1,
  'Service.Group': 1, 'Service.UMask': 1, 'Service.EnvironmentFile': 1, 'Service.ExecStartPre': 1, 'Service.Restart': 1,
  'Service.RestartSec': 1, 'Service.TimeoutStartSec': 1, 'Service.TimeoutStopSec': 1, 'Service.StandardOutput': 1, 'Service.StandardError': 1,
  'Service.StandardInput': 1, 'Service.WorkingDirectory': 1, 'Service.KillMode': 1, 'Service.KillSignal': 1, 'Service.LimitNOFILE': 1,
  'Service.NoNewPrivileges': 187, 'Service.PrivateTmp': 1, 'Service.PrivateDevices': 209, 'Service.PrivateNetwork': 1,
  'Service.ProtectHome': 214, 'Service.ProtectSystem': 214, 'Service.CapabilityBoundingSet': 1, 'Service.AmbientCapabilities': 229,
  'Service.SystemCallFilter': 187, 'Service.SystemCallErrorNumber': 187, 'Service.SystemCallArchitectures': 209,
  'Service.RestrictAddressFamilies': 211, 'Service.ReadWritePaths': 231, 'Service.ReadOnlyPaths': 231, 'Service.BindPaths': 233,
  'Service.ProtectKernelTunables': 232, 'Service.ProtectKernelModules': 232, 'Service.ProtectControlGroups': 232,
  'Service.MemoryDenyWriteExecute': 231, 'Service.RestrictRealtime': 231, 'Service.RemoveIPC': 232, 'Service.RestrictNamespaces': 233,
  'Service.LockPersonality': 235, 'Service.StateDirectory': 235, 'Service.StateDirectoryMode': 235, 'Service.KeyringMode': 235,
  'Service.IPAddressDeny': 235, 'Service.IPAddressAllow': 235, 'Service.RestrictSUIDSGID': 242, 'Service.ProtectHostname': 242,
  'Service.ProtectKernelLogs': 244, 'Service.ProtectClock': 245, 'Service.LoadCredential': 247, 'Service.ProtectProc': 247,
  'Service.ProcSubset': 247, 'Service.Environment': 1, 'Service.SupplementaryGroups': 1, 'Service.RuntimeDirectory': 211,
  'Service.RuntimeDirectoryMode': 211, 'Service.RuntimeDirectoryPreserve': 235, 'Service.ReadWriteDirectories': 1, 'Service.ReadOnlyDirectories': 1,
  'Socket.ListenSequentialPacket': 1, 'Socket.SocketUser': 1, 'Socket.SocketGroup': 1, 'Socket.SocketMode': 1, 'Socket.DirectoryMode': 1,
  'Socket.Service': 1, 'Socket.Accept': 1, 'Socket.Backlog': 1, 'Socket.RemoveOnStop': 1, 'Unit.Description': 1, 'Unit.Documentation': 1,
  'Unit.Wants': 1, 'Unit.After': 1, 'Unit.Requires': 1, 'Unit.ConditionFileIsExecutable': 1, 'Unit.ConditionPathIsDirectory': 1,
  'Unit.ConditionPathExists': 1, 'Install.WantedBy': 1, 'Service.StartLimitInterval': 1, 'Service.StartLimitBurst': 1,
  '@system-service': 239, '@chown': 236, '@setuid': 236,
}

function systemdFixture(version) {
  const root = mkdtempSync(join(tmpdir(), 'systemd-compat-'))
  mkdirSync(join(root, 'lib/systemd'), { recursive: true })
  mkdirSync(join(root, 'bin'))
  const known = Object.entries(since).filter(([, first]) => first <= version).map(([name]) => name)
  writeFileSync(join(root, 'lib/systemd/systemd'), Buffer.from('\0' + known.join('\0') + '\0'))
  writeFileSync(join(root, 'bin/systemctl'), `#!/bin/sh\necho "systemd ${version} (${version})"\n`)
  chmodSync(join(root, 'bin/systemctl'), 0o755)
  return root
}

function render(version, unit) {
  const root = systemdFixture(version)
  try {
    const result = spawnSync('bash', ['-c', `set -Eeuo pipefail\nsource ${JSON.stringify(library)}\nsystemd_compat_render "$1"\nprintf 'DEGRADED=%s\\n' "\${SYSTEMD_COMPAT_DEGRADED[*]:-}"`, 'test', join(repository, unit)],
      { encoding: 'utf8', env: { PATH: `${join(root, 'bin')}:/usr/bin:/bin`, SYSTEMD_COMPAT_ROOT: root } })
    assert.equal(result.status, 0, result.stderr)
    const [dropin, degraded] = result.stdout.split('DEGRADED=')
    return { dropin, degraded: degraded.trim().split(' ').filter(Boolean) }
  } finally { rmSync(root, { recursive: true, force: true }) }
}

const units = {
  agent: 'agents/edge-agent/packaging/systemd/cdnca-edge-agent-root.service',
  helper: 'agents/edge-agent/packaging/systemd/cdnca-edge-agent-helper.service',
  socket: 'agents/edge-agent/packaging/systemd/cdnca-edge-agent-helper.socket',
}

test('installers embed the systemd compatibility library verbatim', () => {
  const source = readFileSync(library, 'utf8')
  for (const [relative, names] of Object.entries(embeds)) if (names.includes('systemd-compat')) assert.equal(embedded(readFileSync(join(repository, relative), 'utf8'), 'systemd-compat').body, source, relative)
})

test('a current systemd gets no compatibility drop-in for any unit', () => {
  for (const unit of Object.values(units)) {
    const { dropin, degraded } = render(255, unit)
    assert.equal(dropin, '', unit)
    assert.deepEqual(degraded, [], unit)
  }
})

test('EL8-class systemd 239: exec type, missing filter groups and newer hardening are handled', () => {
  const helper = render(239, units.helper)
  assert.match(helper.dropin, /^\[Service\]$/m)
  assert.match(helper.dropin, /^Type=simple$/m)
  assert.doesNotMatch(helper.dropin, /^SystemCallFilter=$/m, 'all three filter groups are known at 239')
  assert.deepEqual(helper.degraded.sort(), ['ProtectClock', 'ProtectHostname', 'ProtectKernelLogs', 'RestrictSUIDSGID'].sort())
  assert.equal(render(239, units.agent).dropin, '', 'BindPaths and the agent hardening exist at 239')
})

test('systemd 237 (Ubuntu 18.04) resets a filter whose groups it does not know', () => {
  const helper = render(237, units.helper)
  assert.match(helper.dropin, /^SystemCallFilter=$/m)
  assert.ok(helper.degraded.includes('SystemCallFilter'))
})

test('systemd below 233 replaces BindPaths with an in-namespace bind before exec', () => {
  const agent = render(229, units.agent)
  const lines = agent.dropin.split('\n')
  assert.ok(lines.includes('ExecStart='), 'the packaged ExecStart is reset first')
  const wrapper = lines.find((line) => line.startsWith('ExecStart=/bin/sh -c '))
  assert.ok(wrapper, agent.dropin)
  assert.ok(wrapper.includes(`'mount --bind "$$1" "$$2" && shift 2 && exec "$$@"' sh /var/lib/cdnca-edge-agent-backups/active-state /var/lib/cdnca-edge-agent /usr/lib/cdnca-edge-agent/current/edge-agent -config \${CDNCA_EDGE_CONFIG}`), wrapper)
  assert.ok(lines.includes('ReadWriteDirectories=/etc/cdnca-edge-agent'))
  const helper = render(229, units.helper)
  assert.match(helper.dropin, /^ProtectSystem=full$/m, 'strict is not a valid value before 232')
})

test('apply writes the drop-in only when it is needed', () => {
  for (const [version, expected] of [[255, false], [239, true]]) {
    const root = systemdFixture(version)
    try {
      const result = spawnSync('bash', ['-c', `set -Eeuo pipefail\nsource ${JSON.stringify(library)}\nsystemd_compat_apply "$1" cdnca-edge-agent-helper.service`, 'test', join(repository, units.helper)],
        { encoding: 'utf8', env: { PATH: `${join(root, 'bin')}:/usr/bin:/bin`, SYSTEMD_COMPAT_ROOT: root } })
      assert.equal(result.status, 0, result.stderr)
      const dropin = join(root, 'etc/systemd/system/cdnca-edge-agent-helper.service.d/zz-cdnca-systemd-compat.conf')
      assert.equal(spawnSync('test', ['-f', dropin]).status === 0, expected, String(version))
    } finally { rmSync(root, { recursive: true, force: true }) }
  }
})
