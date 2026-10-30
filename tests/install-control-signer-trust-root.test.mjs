import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

// 节点安装器按离线根验 signer-trust.json，离线根公钥随复制命令 SHA-256 钉住的
// upgrade-trust.json 下发（signer_trust_root）。文档改由 control-api
// `native-backup publish-node-install-trust` 从 control.env 生成（迁移恢复后同一实现重新发布），
// 文档内容（离线根、artifact_trust、宝塔直连端口与私有根）由 Go 单测
// services/control-api/internal/nativebackup/nodeinstalltrust_test.go 覆盖并用 install-node.sh 解析器校验。
const source = readFileSync(new URL('../scripts/install-control.sh', import.meta.url), 'utf8')
const publish = source.match(/^publish_upgrade_trust\(\) \{[\s\S]*?^\}\n/m)?.[0]

// Runs the real function with key generation and file installs stubbed; control-api
// is a stub that writes the document and prints the digest it was told to.
function run(publisher) {
  assert.ok(publish, 'extract the real publish_upgrade_trust function')
  const dir = mkdtempSync(join(tmpdir(), 'cdnca-control-signer-root-'))
  try {
    mkdirSync(join(dir, 'edge-agent'))
    writeFileSync(join(dir, 'control-api'), `#!/bin/bash\n[ "$*" = 'native-backup publish-node-install-trust' ] || exit 9\nTRUST=${JSON.stringify(join(dir, 'edge-agent/upgrade-trust.json'))}\n${publisher}\n`, { mode: 0o755 })
    const script = ['set -Eeuo pipefail', 'fail() { printf "FAIL %s\\n" "$*" >&2; exit 1; }',
      `ED25519_TOOL=fixture_tool; fixture_tool() { case "$1" in genkey) printf 'k\\n' >"$2" ;; pubkey) printf '%s\\n' "$2" ;; esac; }`,
      'install() { while [ "$1" = -d ] || [ "$1" = -m ]; do [ "$1" = -d ] && { shift 3; mkdir -p "$@"; return; }; shift 2; done; cp "$1" "$2"; }',
      'chmod() { :; }',
      `TEMP_DIR=${JSON.stringify(dir)}; DOWNLOAD_DIR=${JSON.stringify(dir)}; UPGRADE_KEY_DIR=${JSON.stringify(join(dir, 'keys'))}`,
      `CONTROL_BINARY=${JSON.stringify(join(dir, 'control-api'))}`,
      publish, 'publish_upgrade_trust', 'printf "%s\\n" "$UPGRADE_TRUST_SHA256"'].join('\n')
    return spawnSync('bash', ['-c', script], { encoding: 'utf8' })
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('the installer publishes the node upgrade trust through control-api and keeps its digest', () => {
  const ok = run('printf \'{"schema":"cdnca.edge-upgrade-trust/v1"}\\n\' >"$TRUST"; sha256sum "$TRUST" | awk \'{print $1}\'')
  assert.equal(ok.status, 0, ok.stderr)
  assert.match(ok.stdout, /^[0-9a-f]{64}\n$/)
  // A digest that does not name the published file stops the install.
  const mismatch = run('printf x >"$TRUST"; printf "%064d\\n" 0')
  assert.notEqual(mismatch.status, 0)
  assert.match(mismatch.stderr, /FAIL published node upgrade trust does not match its digest/)
  const failed = run('exit 1')
  assert.notEqual(failed.status, 0)
  assert.match(failed.stderr, /FAIL failed to build the node upgrade trust document/)
})

test('the offline root pin reaches control.env before the trust document is built from it', () => {
  const main = source.match(/^main\(\) \{[\s\S]*?^\}\n/m)?.[0] ?? ''
  assert.ok(main.indexOf('\n  write_environment\n') > 0 && main.indexOf('\n  write_environment\n') < main.indexOf('\n  publish_upgrade_trust\n'))
  const environment = source.match(/^signer_revocation_environment\(\) \{[\s\S]*?^\}\n/m)?.[0] ?? ''
  for (const key of ['KEY_ID', 'GENERATION', 'PUBLIC_KEY_BASE64']) {
    assert.match(environment, new RegExp(`SIGNER_REVOCATION_CONSUMER_OFFLINE_ROOT_${key}=`), key)
  }
})
