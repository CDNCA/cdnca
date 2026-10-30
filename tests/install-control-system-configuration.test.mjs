import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

test('fresh installation activates the default system configuration after the administrator exists', () => {
  const steps = block('main').split('\n').map((line) => line.trim()).filter((line) => /^[a-z_]+$/.test(line))
  const index = steps.indexOf('bootstrap_system_configuration')
  assert.notEqual(index, -1, 'bootstrap_system_configuration must run during installation')
  assert.ok(index > steps.indexOf('bootstrap_admin'))
  assert.ok(index < steps.indexOf('setup_service'), 'monitoring must be active before the first node can enroll')
})

test('system configuration bootstrap calls the idempotent control-api command and fails closed', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-system-configuration-'))
  try {
    const binary = join(directory, 'control-api')
    writeFileSync(binary, '#!/bin/sh\nprintf "%s|%s\\n" "$DATABASE_URL" "$*" >>"$CALLS"\n[ "${FAIL_BOOTSTRAP:-}" != 1 ]\n')
    chmodSync(binary, 0o755)
    const runStep = (fail) => spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('fail'), 'log() { :; }',
      block('bootstrap_system_configuration'), 'bootstrap_system_configuration'].join('\n')], {
      encoding: 'utf8', env: { ...process.env, CONTROL_BINARY: binary, DATABASE_URL: 'postgresql://localhost/test',
        ADMIN_USERNAME: 'admin', TEMP_DIR: directory, CALLS: join(directory, 'calls'), FAIL_BOOTSTRAP: fail ? '1' : '' },
    })
    const ok = runStep(false)
    assert.equal(ok.status, 0, ok.stderr)
    assert.equal(readFileSync(join(directory, 'calls'), 'utf8'), 'postgresql://localhost/test|bootstrap-system-configuration --username admin\n')
    const failed = runStep(true)
    assert.notEqual(failed.status, 0)
    assert.match(failed.stderr, /system configuration bootstrap failed/)
  } finally { rmSync(directory, { recursive: true }) }
})
