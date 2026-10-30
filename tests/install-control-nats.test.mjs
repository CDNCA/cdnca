import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const body = source.match(/^download_nats_binaries\(\) \{[\s\S]*?^\}/m)?.[0]

function nativeNATSInstallFixture(t, fault = '') {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-nats-install-test-')))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const support = join(root, 'support'), config = join(root, 'config'), destination = join(root, 'installed-nats')
  mkdirSync(join(support, 'scripts/native-runtime'), { recursive: true }); mkdirSync(config)
  const binary = join(support, 'nats-server')
  const bytes = Buffer.from(`#!/bin/sh\nprintf '%s\\n' 'nats-server: v${fault === 'version' ? '2.11.4' : '2.12.15-cdnca.1'}'\n`)
  writeFileSync(binary, bytes, { mode: 0o755 })
  writeFileSync(join(support, 'NATS-LICENSE'), 'NATS test license\n')
  writeFileSync(join(support, 'scripts/native-runtime/native-nats-profile.json'), JSON.stringify({
    server_version: fault === 'profile' ? '2.11.4' : '2.12.15-cdnca.1',
    server_artifact: { sha256: createHash('sha256').update(bytes).digest('hex') },
  }))
  if (fault === 'hash') writeFileSync(binary, 'modified')
  if (fault === 'mode') chmodSync(binary, 0o777)
  if (fault === 'symlink') { rmSync(binary); symlinkSync(join(support, 'NATS-LICENSE'), binary) }
  if (fault.startsWith('existing')) writeFileSync(destination, fault === 'existing exact' ? bytes : 'preserve previous NATS', { mode: 0o755 })
  assert.ok(body)
  const script = ['set -euo pipefail', 'fail() { printf "%s\\n" "$1" >&2; exit 1; }', 'log() { :; }',
    'host_architecture() { printf amd64; }',
    'download_verified() { printf unexpected-network >&2; exit 99; }',
    'sha256sum() { shasum -a 256 "$@"; }',
    `stat() { node -e 'const s=require("fs").statSync(process.argv[1]);console.log(s.uid+":"+(s.mode&4095).toString(8)+":"+s.nlink)' "\${@: -1}"; }`,
    body.replaceAll('0:755:1', `${process.getuid()}:755:1`), 'download_nats_binaries'].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', timeout: 10000, env: { ...process.env,
    NATIVE_SUPPORT: support, NATS_SERVER_BIN: destination, NATS_SERVER_VERSION: '2.12.15-cdnca.1',
    NATS_CLI_BIN: '/usr/bin/true', CONFIG_DIR: config,
  } })
  assert.doesNotMatch(result.stdout + result.stderr, /unexpected-network/)
  return { result, bytes, destination, config }
}

for (const fault of ['', 'existing exact']) {
  test(`NATS installs only the signed pinned binary and license: ${fault || 'fresh'}`, (t) => {
    const fixture = nativeNATSInstallFixture(t, fault)
    assert.equal(fixture.result.status, 0, fixture.result.stderr)
    assert.deepEqual(readFileSync(fixture.destination), fixture.bytes)
    assert.equal(readFileSync(join(fixture.config, 'NATS-LICENSE'), 'utf8'), 'NATS test license\n')
  })
}

for (const fault of ['hash', 'mode', 'symlink', 'profile', 'version', 'existing different']) {
  test(`NATS dependency rejects ${fault} without downloading an alternative`, (t) => {
    const fixture = nativeNATSInstallFixture(t, fault)
    assert.equal(fixture.result.status, 1, fixture.result.stderr)
    assert.match(fixture.result.stderr, /NATS/)
    if (fault === 'existing different') assert.equal(readFileSync(fixture.destination, 'utf8'), 'preserve previous NATS')
    else if (fault !== 'version') assert.equal(existsSync(fixture.destination), false)
    assert.equal(existsSync(join(fixture.config, 'NATS-LICENSE')), false)
  })
}

test('installer no longer constructs an official URL for the custom NATS dependency', () => {
  assert.doesNotMatch(source, /NATS_SERVER_URL|NATS_SERVER_SHA256_URL|nats-io\/nats-server\/releases\/download/)
  assert.match(source, /NATS_SERVER_VERSION="2\.12\.15-cdnca\.1"/)
})
