import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const nodeInstaller = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')
  .replace(/^main "\$@"\s*$/m, '')
function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function renderDefaults(gatewayHost, licensing) {
  const directory = mkdtempSync(join(tmpdir(), 'cdnca-node-defaults-'))
  try {
    mkdirSync(join(directory, 'downloads'))
    const result = spawnSync('bash', ['-c', ['set -Eeuo pipefail', block('write_node_install_defaults'),
      'write_node_install_defaults'].join('\n')], { encoding: 'utf8', env: { ...process.env,
      TEMP_DIR: directory, DOWNLOAD_DIR: join(directory, 'downloads'), GATEWAY_HOST: gatewayHost,
      GATEWAY_ENROLLMENT_PORT: '23001', GATEWAY_AGENT_PORT: '23002',
      LICENSING_SERVER: licensing, UPGRADE_TRUST_SHA256: 'c'.repeat(64) } })
    assert.equal(result.status, 0, result.stderr)
    const file = join(directory, 'downloads/node-install-defaults')
    assert.equal(statSync(file).mode & 0o777, 0o644)
    return readFileSync(file, 'utf8')
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

test('install-control publishes node install defaults that install-node.sh accepts', () => {
  const body = renderDefaults('gw.example', 'https://auth.example')
  assert.equal(body, [`upgrade_trust_sha256=${'c'.repeat(64)}`, 'gateway_enrollment_address=gw.example:23001',
    'gateway_address=gw.example:23002', 'gateway_server_name=gw.example', 'download_fallback_origin=https://auth.example', ''].join('\n'))
  const result = spawnSync('bash', ['-c', `fake=$(mktemp -d); trap 'rm -rf "$fake"' EXIT
printf '#!/usr/bin/env bash\\nprintf "%%s" "$DEFAULTS_BODY"\\n' >"$fake/curl"; chmod +x "$fake/curl"; PATH="$fake:$PATH"
${nodeInstaller}
parse_args --control-plane https://control.example --token fixture-once
load_console_defaults
printf '%s|%s' "$UPGRADE_TRUST_SHA256" "$GATEWAY_ADDRESS"`], { encoding: 'utf8', env: { ...process.env, DEFAULTS_BODY: body } })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, `${'c'.repeat(64)}|gw.example:23002`)
})

test('IPv6 gateways are bracketed and a non-origin licensing server is not used as a fallback', () => {
  const body = renderDefaults('2001:db8::1', 'https://auth.example/path')
  assert.match(body, /^gateway_address=\[2001:db8::1\]:23002$/m)
  assert.doesNotMatch(body, /download_fallback_origin/)
})

test('the console serves install-node.sh from the active release with a published fallback', () => {
  const config = block('write_nginx_config')
  assert.match(config, /location = \/downloads\/install-node\.sh \{\n\s+root \$\{NATIVE_ROOT\}\/current\/static\/web;[\s\S]*?try_files \\\$uri @published_node_installer;/)
  assert.match(config, /location @published_node_installer \{\n\s+root \$\{DATA_DIR\};[\s\S]*?try_files \/downloads\/install-node\.sh =404;/)
  assert.match(block('write_web_runtime_config'), /\n  write_node_install_defaults\n/)
  assert.match(block('download_node_assets'), /install -m 0644 "\$NATIVE_SUPPORT\/scripts\/install-node\.sh" "\$\{DOWNLOAD_DIR\}\/install-node\.sh"/)
})
