import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { spawnSync } from './helpers/large-bash-script.mjs'

// E1 (PJ-E04): a minimal system without nft gets nftables installed; when
// it cannot be installed the installer stops with a clear error instead of
// installing a node that runs without DDoS protection.
const script = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8').replace(/^main "\$@"\s*$/m, '')

// Fake package managers record their arguments; a manager "installs" nft
// (creates the fake binary) only when NFT_INSTALLS=1.
function run(managers, { installs = true, body = 'install_dependencies' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-nft-'))
  try {
    const calls = join(root, 'calls')
    for (const manager of managers) {
      writeFileSync(join(root, manager), `#!/bin/sh
echo "${manager} $*" >>"${calls}"
case " $* " in *" nftables "*) [ "$NFT_INSTALLS" = 1 ] && { printf '#!/bin/sh\\nexit 0\\n' >"${root}/nft"; /bin/chmod +x "${root}/nft"; } ;; esac
exit 0
`)
      chmodSync(join(root, manager), 0o755)
    }
    // Only the fake directory and the shell builtins: no host apt/dnf/yum/nft.
    const result = spawnSync('/bin/bash', ['-c', `${script}\n${body}`], {
      encoding: 'utf8',
      env: { PATH: `${root}:/usr/bin/false-dir-only`, NFT_INSTALLS: installs ? '1' : '0', PROGRESS_PREFIX: '' },
    })
    let recorded = ''
    try { recorded = readFileSync(calls, 'utf8') } catch { /* no manager ran */ }
    return { result, calls: recorded }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

for (const manager of ['apt-get', 'dnf', 'yum']) {
  test(`${manager}: nftables is in the dependency set and nft is checked afterwards`, () => {
    const { result, calls } = run([manager])
    assert.equal(result.status, 0, result.stderr)
    assert.match(calls, new RegExp(`^${manager} .*install .*\\bnftables\\b`, 'm'))
  })

  test(`${manager}: nftables that cannot be installed stops the installer`, () => {
    const { result } = run([manager], { installs: false })
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /nftables \(the nft command\) could not be installed/)
  })
}

test('nft is a required command: its absence triggers the dependency installation', () => {
  const missing = spawnSync('/bin/bash', ['-c', `${script}\ncommand() { [[ "$1" == -v && "$2" != nft ]]; }\nrequire_commands`], { encoding: 'utf8' })
  assert.notEqual(missing.status, 0, 'missing nft must trigger dependency installation')
})

test('dnf is preferred over yum when both exist', () => {
  const { result, calls } = run(['dnf', 'yum'])
  assert.equal(result.status, 0, result.stderr)
  assert.match(calls, /^dnf /m)
  assert.doesNotMatch(calls, /^yum /m)
})
