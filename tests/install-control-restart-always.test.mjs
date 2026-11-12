import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

// The control plane units restart on any
// exit, not only a non-zero one, so a process that ends with status 0 (or is killed by
// a signal) does not leave the console, gateway, NATS or web server down. An explicit
// `systemctl stop` is not restarted, so the upgrade runner's stop-then-swap is unaffected.
// StartLimit* keeps a crash loop from spinning forever.

const installer = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const packaged = readFileSync(new URL('../services/control-api/packaging/systemd/cdnca-control-api.service', import.meta.url), 'utf8')

const units = [
  ['local NATS', 'cat >"/etc/systemd/system/${NATS_SERVICE_NAME}.service" <<EOF\n'],
  ['standalone Agent Gateway', 'cat >"/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" <<UNIT\n'],
  ['Agent Gateway', 'cat >"/etc/systemd/system/${GATEWAY_SERVICE_NAME}.service" <<EOF\n'],
  ['control web', 'cat >"/etc/systemd/system/${WEB_SERVICE_NAME}.service" <<EOF\n'],
  ['control API', 'cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF\n'],
]

function unitText(marker) {
  const start = installer.indexOf(marker)
  assert.notEqual(start, -1, `missing unit ${marker}`)
  assert.equal(installer.indexOf(marker, start + 1), -1, `unit ${marker} is written twice`)
  const end = installer.indexOf('\n[Install]', start)
  assert.ok(end > start && end - start < 2500, `no [Install] section after ${marker}`)
  return installer.slice(start, end)
}

function assertAlwaysWithLimits(text, name) {
  const unit = text.slice(text.indexOf('[Unit]'), text.indexOf('[Service]'))
  assert.match(text, /^Restart=always$/m, `${name} must use Restart=always`)
  assert.doesNotMatch(text, /^Restart=on-failure$/m, `${name} still uses Restart=on-failure`)
  assert.match(text, /^RestartSec=\d+s?$/m, `${name} lost RestartSec`)
  assert.match(unit, /^StartLimitIntervalSec=600$/m, `${name} needs StartLimitIntervalSec in [Unit]`)
  assert.match(unit, /^StartLimitBurst=30$/m, `${name} needs StartLimitBurst in [Unit]`)
}

for (const [name, marker] of units) {
  test(`${name} unit restarts always and is rate limited`, () => assertAlwaysWithLimits(unitText(marker), name))
}

test('the packaged control API unit restarts always and is rate limited', () => {
  assertAlwaysWithLimits(packaged, 'packaged control API unit')
})

test('the limit allows a few minutes of restarts at the unit RestartSec', () => {
  // 30 starts in 600 s at 5 s apart need 150 s of continuous failure to trip.
  const restartSec = Number(/^RestartSec=(\d+)/m.exec(unitText(units[4][1]))[1])
  assert.ok(30 * restartSec <= 600, 'the burst could never be reached inside the interval')
  assert.ok(30 * restartSec >= 120, 'the limit would trip within two minutes')
})

test('the upgrade runner keeps Restart=on-failure', () => {
  const runner = readFileSync(new URL('../deploy/systemd/control-upgrade-runner.service', import.meta.url), 'utf8')
  assert.match(runner, /^Restart=on-failure$/m, 'the upgrade runner exits 0 when an upgrade finishes; it must not be relaunched')
})
