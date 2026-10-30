// uninstall.sh --purge must remove every systemd unit, drop-in and blank-host
// path a native install (scripts/install-node.sh) writes; a leftover makes the
// next first install refuse the host. The installer is the single source.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')
const installer = read('scripts/install-node.sh')
const uninstall = read('agents/edge-agent/packaging/scripts/uninstall.sh')
const purge = uninstall.slice(uninstall.indexOf('if [ "${purge}" = true ]; then\n  # Units'))
const constants = Object.fromEntries([...installer.matchAll(/^readonly ([A-Z_]+)="([^"$]*)"$/gm)].map((m) => [m[1], m[2]]))
const expand = (value) => value.replace(/\$\{?([A-Z_]+)\}?/g, (_, name) => constants[name] ?? `<${name}>`)
const listOf = (name) => {
  const m = purge.match(new RegExp(`^  ${name}='([^']+)'$`, 'm'))
  assert.ok(m, `uninstall.sh --purge has no ${name} list`)
  return m[1].split(' ')
}

test('purge removes every unit the installer writes under /usr/lib/systemd/system', () => {
  const body = installer.slice(installer.indexOf('start_packaging_helper() {'), installer.indexOf('probe_packaging_helper() {'))
  const loop = body.match(/for unit in ([^;]+); do\n\s+install -m 0644 "\$\{NATIVE_RELEASE\}\/packaging\/systemd\/\$\{unit\}" "\$\{SYSTEMD_PACKAGE_DIR\}\/\$\{unit\}"/)
  assert.ok(loop, 'installer helper unit loop not found')
  const installed = loop[1].trim().split(/\s+/)
  assert.deepEqual([...installed].sort(), [...listOf('helper_units')].sort())
  // The Agent unit itself comes from the packaging transaction and is removed by the default uninstall.
  assert.match(uninstall, /^  \/usr\/lib\/systemd\/system\/cdnca-edge-agent\.service \\$/m)
  // Units the installer enables leave a wants link; the socket is the only one enabled outside the packaging driver.
  const enabled = [...installer.matchAll(/systemctl enable --now ([a-z0-9.-]+)/g)].map((m) => m[1])
  for (const unit of enabled) assert.ok(installed.includes(unit), `enabled unit ${unit} is not a helper unit`)
  assert.match(purge, /systemctl disable cdnca-edge-agent-helper\.socket/)
})

test('purge removes every systemd compatibility drop-in the installer may render', () => {
  const rendered = new Set()
  for (const m of installer.matchAll(/systemd_compat_apply "[^"]+" "([^"]+)"/g)) {
    const name = expand(m[1])
    if (name === '$unit') {
      const loops = [...installer.slice(0, m.index).matchAll(/for unit in ([^;]+); do/g)]
      const loop = loops[loops.length - 1]
      for (const unit of loop[1].trim().split(/\s+/)) rendered.add(expand(unit))
    } else rendered.add(name)
  }
  assert.ok(rendered.size >= 3, [...rendered].join(','))
  const removed = new Set(listOf('compat_units'))
  for (const unit of rendered) assert.ok(removed.has(unit), `purge leaves drop-in for ${unit}`)
})

test('every unit the blank-host gate refuses is removed by uninstall or never installed by the node installer', () => {
  const gate = installer.slice(installer.indexOf('assert_blank_host() {'), installer.indexOf('# Install record (PJ-E06). The file'))
  const units = gate.match(/for unit in ([^;]+); do/)[1].replace(/\\\n/g, ' ').trim().split(/\s+/).map(expand)
  const writtenByInstaller = new Set([`${constants.SERVICE_NAME}.service`, ...listOf('helper_units')])
  for (const unit of units) {
    if (!writtenByInstaller.has(unit)) {
      assert.doesNotMatch(installer, new RegExp(`install -m 0644 [^\\n]*${unit.replace(/\./g, '\\.')}`), `${unit} is installed but not purged`)
      continue
    }
    const removedByDefault = unit === 'cdnca-edge-agent.service' && /\/usr\/lib\/systemd\/system\/cdnca-edge-agent\.service/.test(uninstall)
    assert.ok(removedByDefault || listOf('helper_units').includes(unit), `purge leaves ${unit}`)
  }
})

test('every blank-host path the installer itself creates is removed by purge', () => {
  const gate = installer.slice(installer.indexOf('assert_blank_host() {'), installer.indexOf('# Install record (PJ-E06). The file'))
  const paths = gate.match(/for path in ([^;]+); do/)[1].replace(/\\\n/g, ' ').trim().split(/\s+/).map((p) => expand(p.replace(/"/g, '')))
  // Never created by this installer: a foreign or pre-native runtime the gate guards against.
  const foreign = new Set([constants.LEGACY_INSTALL_ROOT, '/var/lib/site-runtime', '/usr/sbin/nginx'])
  const allowed = uninstall.match(/remove_tree\(\) \{[^]*?case "\$\{candidate\}" in\n([^]*?)\) ;;/)[1]
  const removedFiles = new Set(['/usr/libexec/cdnca-edge-agent-helper', '/var/lib/cdnca-edge-agent-packaging'])
  const links = new Set([...purge.matchAll(/^    (\/[^:\s]+):\/opt\/cdnca-node\//gm)].map((m) => m[1]))
  for (const path of paths) {
    if (foreign.has(path)) continue
    assert.ok(!path.includes('<'), `unresolved installer constant in ${path}`)
    const covered = links.has(path) || removedFiles.has(path) ||
      new RegExp(`\\*${path.replace(/[.]/g, '\\.')}(\\||\\\\|$)`, 'm').test(allowed) &&
        (uninstall.includes(`remove_tree "$(root_path ${path})"`))
    assert.ok(covered, `purge leaves blank-host path ${path}`)
  }
})

test('default uninstall keeps helper units, identity and native state (purge-only removal)', () => {
  const before = uninstall.slice(uninstall.indexOf('validate_retained_state_layout\n'), uninstall.indexOf('if [ "${purge}" = true ]; then\n  # Units'))
  assert.ok(before.length > 0)
  assert.doesNotMatch(before, /cdnca-edge-agent-helper|\/opt\/cdnca-node|cdnca-node-install|systemctl/)
})
