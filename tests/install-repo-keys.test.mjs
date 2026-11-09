// 软件源签名公钥随安装器内置（scripts/lib/repo-keys.sh），安装时不在线取。
// 核对：主钥指纹与上游公布值一致、主钥与子钥都没有过期时间、内容与 2026-11-09 取回的上游文件一致，
// 嵌入的两个脚本与库逐字一致，执行代码里不再在线取公钥。
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import { embedded, embeds } from '../scripts/sync-install-preflight.mjs'

const read = (relative) => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')
const libraryPath = new URL('../scripts/lib/repo-keys.sh', import.meta.url).pathname
const library = read('scripts/lib/repo-keys.sh')

// 名称 -> [主钥指纹, 上游文件 SHA-256（去掉末尾换行）]。指纹出处见库文件头注释。
const keys = {
  'pgdg-apt': ['B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8', 'ce02d52e40c7253a78a4124977526927552d95b15274285633bdefda1d05436d'],
  clickhouse: ['3A9EA1193A97B548BE1457D48919F6BD2B48D754', '74c1dfd89393b27c5739ee579a5af661ebe628cef9c33222c6fb29d0b8d42ad0'],
  'pgdg-rhel': ['D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20', '39b300676137bd3b801fa4cae9c7d2daf35d5cc61fcef26580eda69b1ac45d20'],
  'epel-8': ['94E279EB8D8F25B21810ADF121EA45AB2F86D6A1', '6cca72992a283ad3b0c346db30463ad64d6a9d8275d692a3fc73dcc1e47bb1c1'],
  'epel-9': ['FF8AD1344597106ECE813B918A3872BF3228467C', '2e40e09362685bdfa27b59344a0f507b505c411fd052c4fee8dd6525ad0a8aff'],
  'epel-10': ['7D8D15CBFC4E62688591FB2633D98517E37ED158', 'fbcb0ca25463dd8524c92e0794584d110b13a6343bf2fa2886076356c246db64'],
}
const armor = (name) => spawnSync('bash', ['-c', `. '${libraryPath}'; repo_key_armor "$1"`, 'x', name], { encoding: 'utf8' })
const hasGpg = spawnSync('gpg', ['--version']).status === 0

test('every bundled key matches the upstream file it was taken from', () => {
  for (const [name, [, sha256]] of Object.entries(keys)) {
    const result = armor(name)
    assert.equal(result.status, 0, `${name}: ${result.stderr}`)
    assert.match(result.stdout, /^-----BEGIN PGP PUBLIC KEY BLOCK-----\n[\s\S]*\n-----END PGP PUBLIC KEY BLOCK-----\n$/, name)
    assert.equal(createHash('sha256').update(result.stdout.replace(/\n+$/, '')).digest('hex'), sha256, name)
  }
  assert.notEqual(armor('unknown').status, 0)
  assert.equal(armor('unknown').stdout, '')
})

test('every bundled key has the pinned primary fingerprint and no expiry on the primary key or any subkey', { skip: !hasGpg && 'gpg not installed' }, (t) => {
  const home = mkdtempSync(join(tmpdir(), 'cdnca-repo-keys-gpg-'))
  t.after(() => rmSync(home, { recursive: true, force: true }))
  for (const [name, [fingerprint]] of Object.entries(keys)) {
    const listing = spawnSync('gpg', ['--no-options', '--batch', '--homedir', home, '--with-colons', '--show-keys'], { input: armor(name).stdout, encoding: 'utf8' })
    assert.equal(listing.status, 0, `${name}: ${listing.stderr}`)
    const records = listing.stdout.split('\n').map((line) => line.split(':'))
    const primaries = records.filter((fields) => fields[0] === 'pub')
    assert.equal(primaries.length, 1, `${name} must hold exactly one primary key`)
    const first = records.findIndex((fields) => fields[0] === 'pub')
    assert.equal(records[first + 1][0], 'fpr')
    assert.equal(records[first + 1][9], fingerprint, name)
    for (const fields of records.filter((entry) => entry[0] === 'pub' || entry[0] === 'sub')) {
      assert.equal(fields[6], '', `${name}: a key expires (${fields[4]})`)
      assert.notEqual(fields[1], 'r', `${name}: a key is revoked (${fields[4]})`)
    }
  }
})

test('the dependency helper embeds the library verbatim and pins the same fingerprints', () => {
  for (const relative of ['scripts/native-runtime/install-ubuntu-dependencies.sh']) {
    assert.ok(embeds[relative].includes('repo-keys'), `${relative} not in sync list`)
    assert.equal(embedded(read(relative), 'repo-keys').body, library, `${relative} is stale; run node scripts/sync-install-preflight.mjs`)
  }
  const helper = read('scripts/native-runtime/install-ubuntu-dependencies.sh')
  for (const [name, [fingerprint]] of Object.entries(keys)) {
    if (name.startsWith('epel-')) assert.match(helper, new RegExp(`${name.slice(5)}\\) native_dependencies_verify_key "\\$key_dir/epel\\.asc" ${fingerprint}`))
    else assert.ok(helper.includes(fingerprint), `${name} fingerprint not pinned in the helper`)
  }
})

test('the dependency helper writes the bundled keys without any network access (apt and EL 8/9/10)', { skip: !hasGpg && 'gpg not installed' }, (t) => {
  const root = mkdtempSync(join(tmpdir(), 'cdnca-repo-keys-helper-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const helper = new URL('../scripts/native-runtime/install-ubuntu-dependencies.sh', import.meta.url).pathname
  // The helper refuses existing key/source paths, so every run starts from an empty directory.
  const run = (setup) => spawnSync('bash', ['-c', [`set -Eeuo pipefail; source '${helper}'`, 'PATH="$TEST_PATH"', 'rm -rf -- "${TEST_ROOT:?}"/*',
    'curl() { echo network >&2; return 7; }; wget() { echo network >&2; return 4; }',
    'native_dependencies_write_new() { printf "%s\\n" "$1" >>"$TEST_ROOT/written"; [[ $1 != *.asc && $1 != */CDNCA-* ]] || printf "%s" "$3" >"$TEST_ROOT/$(basename "$1")"; }',
    `DEPS_PG_KEY="$TEST_ROOT/pg.asc" DEPS_CH_KEY="$TEST_ROOT/ch.asc" DEPS_PG_SOURCE="$TEST_ROOT/pg.sources" DEPS_CH_SOURCE="$TEST_ROOT/ch.list"`,
    setup, 'native_dependencies_repositories'].join('\n')], { encoding: 'utf8', env: { ...process.env, TEST_ROOT: root, TEST_PATH: process.env.PATH } })
  const fingerprint = (file) => spawnSync('gpg', ['--no-options', '--batch', '--with-colons', '--show-keys', join(root, file)], { encoding: 'utf8' })
    .stdout.split('\n').find((line) => line.startsWith('fpr:')).split(':')[9]
  let result = run('DEPS_PG_SUITE=noble-pgdg')
  assert.equal(result.status, 0, result.stderr)
  assert.doesNotMatch(result.stderr, /network/)
  assert.equal(fingerprint('pg.asc'), keys['pgdg-apt'][0])
  assert.equal(fingerprint('ch.asc'), keys.clickhouse[0])
  for (const major of ['8', '9', '10']) {
    rmSync(join(root, 'written'), { force: true })
    result = run(`DEPS_FAMILY=rhel DEPS_EL_MAJOR=${major} DEPS_PG_SUITE=EL-${major}-x86_64 DEPS_EPEL_KEY="$TEST_ROOT/CDNCA-EPEL" DEPS_EPEL_SOURCE="$TEST_ROOT/epel.repo"`)
    assert.equal(result.status, 0, result.stderr)
    assert.doesNotMatch(result.stderr, /network/)
    assert.equal(fingerprint('pg.asc'), keys['pgdg-rhel'][0])
    assert.equal(fingerprint('CDNCA-EPEL'), keys[`epel-${major}`][0])
  }
  result = run('DEPS_FAMILY=rhel DEPS_EL_MAJOR=7 DEPS_PG_SUITE=EL-7-x86_64 DEPS_EPEL_KEY="$TEST_ROOT/CDNCA-EPEL" DEPS_EPEL_SOURCE="$TEST_ROOT/epel.repo"')
  assert.notEqual(result.status, 0)
  assert.match(result.stderr, /unsupported_os/)
})

test('no installer code downloads a repository key any more', () => {
  const code = (text) => text.split('\n').filter((line) => !/^\s*#/.test(line)).join('\n')
  for (const relative of ['scripts/install-control.sh', 'scripts/native-runtime/install-ubuntu-dependencies.sh']) {
    assert.doesNotMatch(code(read(relative)), /media\/keys\/|repomd\.xml\.key|epel\/RPM-GPG-KEY|yum\/keys\/|_KEY_URL/, relative)
  }
})
