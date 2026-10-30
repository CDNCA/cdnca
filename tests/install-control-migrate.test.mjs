import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
function block(name) {
  const value = source.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'))?.[0]
  assert.ok(value, `missing ${name}`)
  return value
}

test('migrate-from is dispatched before the fresh-install argument parser', () => {
  const main = block('main')
  // enable-gateway-access（918327477）、--cleanup-failed（AUDIT-1029 ①-12）与 --mode gateway (ADR 0013 GW-10) are the only other dispatches before parse_args.
  assert.match(main, /^main\(\) \{\n  \[ "\$\{1:-\}" != migrate-from \] \|\| \{ shift; migrate_main "\$@"; return; \}\n  \[ "\$\{1:-\}" != enable-gateway-access \] \|\| \{ shift; gateway_access_main "\$@"; return; \}\n  \[ "\$\{1:-\}" != --cleanup-failed \] \|\| \{ shift; cleanup_failed_main "\$@"; return; \}\n  ! gateway_mode_requested "\$@" \|\| \{ INSTALL_MODE=gateway; gateway_main "\$@"; return; \}\n  parse_args "\$@"/)
})

test('fresh installs keep the dependency installer and enable the backup agent', () => {
  const main = block('main')
  assert.ok(main.indexOf('setup_backup_agent') > main.indexOf('verify_native_plan_source'))
  assert.ok(main.indexOf('setup_backup_agent') < main.indexOf('print_gateway_ports'))
  const setup = block('setup_backup_agent')
  assert.match(setup, /support\/install-ubuntu-dependencies\.sh/)
  assert.match(setup, /native-backup install-units/)
  // The keys exist before the timer can start the agent (first-use race, 73 on 10-24).
  assert.ok(setup.indexOf('native-backup fingerprint') < setup.indexOf('native-backup install-units'))
})

test('migration orders freeze, transfer, restore and verification and rolls back on failure', () => {
  const migrate = block('migrate_main')
  const order = ['assert_fresh_installation', 'native-backup status', 'run_preflight', 'release.manifest.json',
    'install-ubuntu-dependencies.sh" install', 'new-identity', 'create --reason migration --hold', 'tar -C', 'native-backup restore',
    'verify-migration']
  let last = -1
  for (const step of order) {
    const at = migrate.indexOf(step, last + 1)
    assert.ok(at > last, `${step} out of order`)
    last = at
  }
  // The copied binary must match the old host's signed release manifest.
  assert.match(migrate, /select\(\.path == "bin\/control-api"\) \| \.sha256/)
  // A failed transfer or restore restarts the old control plane.
  assert.equal((migrate.match(/migrate_rollback\n/g) || []).length, 1)
  assert.match(migrate, /bundle transfer failed/)
  assert.match(migrate, /restore failed/)
  // Verification failure leaves the old host frozen (no rollback).
  const verify = migrate.slice(migrate.indexOf('verify-migration'))
  assert.doesNotMatch(verify.split('fail ')[0], /migrate_rollback/)
  // The new host never generates identity or activates.
  assert.doesNotMatch(migrate, /generate_identity|activate|prepare_database|configure_clickhouse|install-rustfs/)
})
