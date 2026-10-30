import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from './helpers/large-bash-script.mjs'
import { hostEd25519Tool } from './helpers/ed25519-tool-host.mjs'
import { offlineRoot, signerTrustDocument, signSignerTrust } from './helpers/signer-trust-fixture.mjs'
import test from 'node:test'

// 签名者信任文档（签名密钥泄露吊销·节点侧）：安装器先按离线根公钥验签，
// 验过的文档才用来吊销 artifacts.json 里的公钥；验签失败不改 artifacts.json、安装停下。
const source = readFileSync(new URL('../scripts/install-node.sh', import.meta.url), 'utf8')

function block(name) {
  const lines = source.split('\n')
  const start = lines.findIndex((line) => line.startsWith(`${name}() {`))
  assert.notEqual(start, -1, `missing ${name}`)
  const end = lines.findIndex((line, index) => index > start && line === '}')
  return lines.slice(start, end + 1).join('\n')
}

function key(type = 'ed25519') {
  const { publicKey } = type === 'ec' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('ed25519')
  return { pem: publicKey.export({ type: 'spki', format: 'pem' }),
    sha256: createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex') }
}

const root = offlineRoot()

// published: the signer-trust.json bytes the control plane serves (null = 404); pin: the
// upgrade trust's signer_trust_root ('' = the control plane was installed without one);
// pinned: the upgrade trust's artifact_trust keys (null = no pin).
function run(keys, published, pin = root.pin, pinned = keys) {
  const dir = mkdtempSync(join(tmpdir(), 'node-signer-revocation-'))
  const trust = join(dir, 'artifacts.json')
  writeFileSync(trust, JSON.stringify({ version: 1, keys }))
  chmodSync(trust, 0o400)
  const artifactPin = join(dir, 'artifact-trust.json')
  if (pinned) writeFileSync(artifactPin, JSON.stringify({ version: 1, keys: pinned }))
  const served = join(dir, 'served.json')
  if (published) writeFileSync(served, published)
  const script = ['set -Eeuo pipefail', 'log() { printf "%s\\n" "$*" >&2; }', 'fail() { printf "FAIL %s\\n" "$*" >&2; exit 1; }',
    `curl_download() { [ -f ${JSON.stringify(served)} ] || return 22; local out; while [ "$#" -gt 0 ]; do [ "$1" = --output ] && out=$2; shift; done; cp ${JSON.stringify(served)} "$out"; }`,
    `resolve_ed25519_tool() { ED25519_TOOL=${JSON.stringify(hostEd25519Tool().path)}; }`,
    `SIGNER_TRUST_ROOT=${JSON.stringify(pin ? JSON.stringify(pin) : '')}`, "SIGNER_TRUST_DOCUMENT=''",
    `ARTIFACT_TRUST_PIN=${JSON.stringify(pinned ? artifactPin : '')}`,
    block('fetch_signer_trust'), block('verify_signer_trust'), block('require_pinned_artifact_trust'), block('apply_signer_revocations'),
    'fetch_signer_trust', `require_pinned_artifact_trust ${JSON.stringify(trust)}`, `apply_signer_revocations ${JSON.stringify(trust)}`].join('\n')
  const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH, TEMP_DIR: dir,
    ARTIFACT_TRUST_URL: 'https://control.example/downloads/edge-agent/artifacts.json' } })
  return { result, trust: JSON.parse(readFileSync(trust, 'utf8')) }
}

const revoking = (entries, signer = root, options) => signSignerTrust(signerTrustDocument({ revoked: entries }), signer, options)
const compromised = (id, extra = {}) => ({ key_id: id, revoked_at: '2026-10-17T07:00:00Z', reason: 'signer_compromise', ...extra })

test('revoked artifact keys are removed by key ID or public key fingerprint before the package is verified', () => {
  const old = key(), renamed = key('ec'), publisher = key()
  const { result, trust } = run([{ key_id: 'release-old', public_key_pem: old.pem },
    { key_id: 'release-renamed', public_key_pem: renamed.pem }, { key_id: 'edge-publish', public_key_pem: publisher.pem }],
  revoking([compromised('release-old'), compromised('other-name', { public_key_sha256: renamed.sha256 })]))
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(trust.keys.map((entry) => entry.key_id), ['edge-publish'])
  assert.match(result.stderr, /release-old release-renamed/)
})

test('no published document or nothing revoked leaves artifacts.json untouched', () => {
  const keys = [{ key_id: 'release', public_key_pem: key().pem }]
  for (const published of [null, revoking([])]) {
    const { result, trust } = run(keys, published)
    assert.equal(result.status, 0, result.stderr)
    assert.deepEqual(trust.keys, keys)
  }
})

test('a document that does not verify against the offline root changes nothing and stops the install', () => {
  const keys = [{ key_id: 'release', public_key_pem: key().pem }, { key_id: 'other', public_key_pem: key().pem }]
  const revoke = [compromised('release')]
  const forged = offlineRoot()
  const otherGeneration = offlineRoot('cdnca-offline-root', 2)
  for (const [label, published, pin] of [
    ['another root', revoking(revoke, forged), undefined],
    ['same key id, another generation', revoking(revoke, otherGeneration), undefined],
    ['document changed after signing', revoking([], root, { tamper: (document) => ({ ...document, revoked_keys: revoke }) }), undefined],
    ['signature removed', revoking(revoke).replace(/"signature":"[^"]+"/, '"signature":""'), undefined],
    ['unsigned structure only', JSON.stringify({ document: signerTrustDocument({ revoked: revoke }) }), undefined],
    ['not canonical (spaces)', JSON.stringify(JSON.parse(revoking(revoke)), null, 1), undefined],
    ['unknown document field', revoking(revoke, root, { tamper: (document) => ({ ...document, extra: true }) }), undefined],
    ['no pin on this control plane', revoking(revoke), null],
  ]) {
    const { result, trust } = run(keys, published, pin === null ? '' : root.pin)
    assert.notEqual(result.status, 0, label)
    assert.match(result.stderr, /FAIL /, label)
    assert.deepEqual(trust.keys, keys, `${label}: artifacts.json must not change`)
  }
  assert.match(run(keys, revoking(revoke, forged)).result.stderr, /does not verify against the pinned offline root \(cdnca-offline-root generation 1\)/)
  assert.match(run(keys, revoking(revoke), '').result.stderr, /--signer-revocation-offline-root-\*/)
})

test('revoking every key fails the install', () => {
  const { result } = run([{ key_id: 'release', public_key_pem: key().pem }], revoking([compromised('release')]))
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /FAIL every artifact trust key is revoked/)
})

// fix-r1c（freeze-audit2 第 2 项，方案 A）：artifacts.json 不签名、运行期会被主控按信任文档改写，
// 不能钉整份摘要；节点要求其中每把公钥（key_id + 公钥指纹）都在 upgrade-trust 的 artifact_trust
// 或按离线根验过的信任文档 usage="" trusted_keys 里，否则拒装。
test('an artifact key the pin and the verified document do not authorize stops the install', () => {
  const release = key(), publisher = key(), attacker = key()
  const pinned = [{ key_id: 'release', public_key_pem: release.pem }, { key_id: 'edge-publish', public_key_pem: publisher.pem }]
  const lease = { key_id: 'lease-2026', public_key_pem: key().pem, usage: 'installation-ban' }
  for (const [label, keys, published] of [
    ['extra key, no document', [...pinned, { key_id: 'attacker', public_key_pem: attacker.pem }], null],
    ['extra key, verified document without it', [...pinned, { key_id: 'attacker', public_key_pem: attacker.pem }], revoking([])],
    ['pinned key ID with another public key', [{ key_id: 'release', public_key_pem: attacker.pem }, pinned[1]], null],
    ['installation-ban key is not an artifact key', [...pinned, { key_id: lease.key_id, public_key_pem: lease.public_key_pem }],
      signSignerTrust(signerTrustDocument({ trusted: [lease] }), root)],
  ]) {
    const { result, trust } = run(keys, published, root.pin, pinned)
    assert.notEqual(result.status, 0, label)
    assert.match(result.stderr, /FAIL artifacts\.json carries artifact keys \((attacker|release|lease-2026)\) that neither the pinned upgrade trust/, label)
    assert.deepEqual(trust.keys, keys, `${label}: artifacts.json must not change`)
  }
  // A forged document that "adds" the key never gets that far.
  const forged = signSignerTrust(signerTrustDocument({ trusted: [{ key_id: 'attacker', public_key_pem: attacker.pem }] }), offlineRoot())
  const { result } = run([...pinned, { key_id: 'attacker', public_key_pem: attacker.pem }], forged, root.pin, pinned)
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /does not verify against the pinned offline root/)
  // No artifact_trust pin: refused.
  const missing = run(pinned, null, root.pin, null).result
  assert.notEqual(missing.status, 0)
  assert.match(missing.stderr, /FAIL node upgrade trust carries no artifact key pin/)
})

test('after a revocation or rotation the control plane rewrote artifacts.json and new nodes still install', () => {
  const old = key(), publisher = key(), next = key('ec')
  const pinned = [{ key_id: 'edge-publish', public_key_pem: publisher.pem }, { key_id: 'release-2026', public_key_pem: old.pem }]
  const rotated = signSignerTrust(signerTrustDocument({ revision: 2,
    trusted: [{ key_id: 'release-2027', public_key_pem: next.pem }, { key_id: 'lease-2026', public_key_pem: key().pem, usage: 'installation-ban' }],
    revoked: [compromised('release-2026')] }), root)
  // edgesignertrust.PublishDownloads already applied it (release-2026 gone, release-2027 added) ...
  const refreshed = run([pinned[0], { key_id: 'release-2027', public_key_pem: next.pem }], rotated, root.pin, pinned)
  assert.equal(refreshed.result.status, 0, refreshed.result.stderr)
  assert.deepEqual(refreshed.trust.keys.map((entry) => entry.key_id), ['edge-publish', 'release-2027'])
  // ... or not yet (still the install-time copy): the node drops the revoked key itself.
  const stale = run(pinned, rotated, root.pin, pinned)
  assert.equal(stale.result.status, 0, stale.result.stderr)
  assert.deepEqual(stale.trust.keys.map((entry) => entry.key_id), ['edge-publish'])
})

test('the installer verifies the document right after loading the artifact trust document, with the pin from the upgrade trust', () => {
  assert.match(block('install_trust_material'),
    /artifact trust document is invalid'\n {2}fetch_signer_trust\n {2}require_pinned_artifact_trust "\$ARTIFACT_TRUST_FILE"\n {2}apply_signer_revocations "\$ARTIFACT_TRUST_FILE"\n/)
  assert.match(block('install_upgrade_trust'), /ARTIFACT_TRUST_PIN="\$\{TEMP_DIR\}\/upgrade-trust\/artifact-trust\.json"/)
  const main = source.slice(source.indexOf('\nmain() {'))
  assert.ok(main.indexOf('\n  install_upgrade_trust\n') < main.indexOf('\n  install_trust_material\n'))
  assert.match(block('install_upgrade_trust'), /SIGNER_TRUST_ROOT=\$\(jq -c '\.signer_trust_root \/\/ empty' <<<"\$facts"\)/)
  assert.doesNotMatch(block('apply_signer_revocations'), /curl_download/)
})
