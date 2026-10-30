// deploy/systemd/cdnca-control-optional.env.example documents the optional
// control-api runtimes that fresh installs leave off. Keep it honest: every key
// must be read by control-api, none may shadow a generated key, and the drop-in
// must load it after the generated environment files.
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import test from 'node:test'

const read = (name) => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8')
const template = read('deploy/systemd/cdnca-control-optional.env.example')
const keys = [...template.matchAll(/^# ([A-Z][A-Z0-9_]+)=/gm)].map((match) => match[1])
const commandDir = new URL('../services/control-api/cmd/control-api/', import.meta.url)
const code = readdirSync(commandDir).filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
  .map((name) => readFileSync(new URL(name, commandDir), 'utf8')).join('\n')

test('every template key is read by control-api', () => {
  assert.ok(keys.length >= 15, `only ${keys.length} keys parsed`)
  assert.equal(new Set(keys).size, keys.length, 'duplicate keys')
  for (const key of keys) assert.ok(code.includes(`"${key}"`), `${key} is not read by cmd/control-api`)
})

test('template keys do not shadow generated control environment', () => {
  const installer = read('scripts/install-control.sh')
  const start = installer.indexOf('cat >"${CONFIG_DIR}/control.env" <<EOF')
  const generated = installer.slice(start, installer.indexOf('\nEOF\n', start))
  const runtime = read('scripts/native-runtime/configure-control-runtime.py')
  for (const key of keys) {
    assert.ok(!new RegExp(`^${key}=`, 'm').test(generated), `${key} is generated in control.env`)
    assert.ok(!runtime.includes(`"${key}"`), `${key} is generated in runtime-extra.env`)
  }
  assert.ok(!keys.includes('LICENSE_SERVICE_URL'), 'LICENSE_SERVICE_URL belongs to control.env')
})

test('template carries no secret values and the drop-in loads it last', () => {
  for (const line of template.split('\n').filter((entry) => /^# [A-Z][A-Z0-9_]+=/.test(entry))) {
    const value = line.slice(line.indexOf('=') + 1)
    assert.ok(!/BEGIN|PRIVATE KEY|[A-Za-z0-9+/]{40,}={0,2}/.test(value), `suspicious value: ${line}`)
  }
  const dropin = read('deploy/systemd/cdnca-control-api-optional.conf.example')
  assert.match(dropin, /^\[Service\]\nEnvironmentFile=\/etc\/cdnca-control\/optional\.env$/m)
  // Drop-ins load after the unit's own EnvironmentFile lines; 60- sorts after the
  // DNS (50-) and certificate (30-) runtime drop-ins used by existing consoles.
  assert.match(dropin, /service\.d\/60-optional\.conf/)
})
