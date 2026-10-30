import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

const files = {
  'edge-agent': 'isolated binary fixture\n',
  'edge-agent.provenance.json': '{"fixture":"来源"}\n',
  'edge-agent.spdx.json': '{"fixture":"spdx"}\n',
}

function runMetadataBuild(t, flavor, fault = '', target = 'edge-agent', metadata = true) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'cdnca-edge-metadata-test-')))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const repo = join(root, 'repo'), bin = join(root, 'bin'), output = join(root, 'release'), calls = join(root, 'stat-calls')
  for (const directory of ['scripts', 'agents/edge-agent/packaging/build', 'libs/autodefense/detect', 'libs/autodefense/mine', 'libs/autodefense/sketch', 'libs/edgeconfig', 'libs/entitlement', 'libs/rulepack', 'proto/gen/go']) {
    mkdirSync(join(repo, directory), { recursive: true })
  }
  mkdirSync(bin)
  copyFileSync(new URL('./edge-agent-release-build.sh', import.meta.url), join(repo, 'scripts/edge-agent-release-build.sh'))
  copyFileSync(new URL('../agents/edge-agent/packaging/build/contract.json', import.meta.url), join(repo, 'agents/edge-agent/packaging/build/contract.json'))
  writeFileSync(join(repo, 'agents/edge-agent/packaging/build/recipe.sh'), '#!/usr/bin/env bash\nexit 99\n')
  writeFileSync(join(bin, 'docker'), `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path')
const args = process.argv.slice(2)
const parent = args.find((arg) => arg.endsWith(':/output:rw')).slice(0, -':/output:rw'.length)
const output = path.join(parent, args[args.indexOf('--output-dir') + 1].slice('/output/'.length))
fs.mkdirSync(output, { recursive: true })
for (const [name, body] of Object.entries(${JSON.stringify(files)})) fs.writeFileSync(path.join(output, name), body)
`, { mode: 0o755 })
  if (flavor !== 'host') writeFileSync(join(bin, 'stat'), `#!/usr/bin/env node
const fs = require('node:fs'), path = require('node:path')
const args = process.argv.slice(2), file = args.at(-1)
fs.appendFileSync(process.env.EDGE_METADATA_TEST_CALLS, args[0] + ':' + path.basename(file) + '\\n')
if (args[0] === '-f' && process.env.EDGE_METADATA_TEST_FLAVOR === 'gnu') {
  process.stdout.write('  File: "' + file + '"\\n    ID: deadbeef Namelen: 255 Type: ext2/ext3\\n')
  process.exit(1)
}
if ((args[0] !== '-f' || args[1] !== '%z') && (args[0] !== '-c' || args[1] !== '%s')) process.exit(90)
if (path.basename(file) === process.env.EDGE_METADATA_TEST_TARGET) {
  if (process.env.EDGE_METADATA_TEST_FAULT === 'failed-with-output') { process.stdout.write('123\\n'); process.exit(1) }
  if (process.env.EDGE_METADATA_TEST_FAULT === 'fractional-success') { process.stdout.write('1.5\\n'); process.exit(0) }
}
process.stdout.write(String(fs.statSync(file).size) + '\\n')
`, { mode: 0o755 })
  const args = [join(repo, 'scripts/edge-agent-release-build.sh'), '--output-dir', output, '--arch', 'amd64',
    '--version', '1.0.22', '--build-id', 'metadata-fixture', '--source-repository', 'https://example.invalid/source',
    '--source-commit', 'a'.repeat(40), '--source-date-epoch', '1791676800']
  if (metadata) args.push('--metadata-file', join(output, 'release-inputs.json'))
  const result = spawnSync('bash', args, { encoding: 'utf8', timeout: 10000, env: {
    ...process.env, PATH: `${bin}:${process.env.PATH}`, TMPDIR: root,
    EDGE_METADATA_TEST_CALLS: calls, EDGE_METADATA_TEST_FLAVOR: flavor,
    EDGE_METADATA_TEST_FAULT: fault, EDGE_METADATA_TEST_TARGET: target,
  } })
  assert.equal(result.error, undefined)
  assert.equal(readdirSync(root).some((name) => name.startsWith('.edge-release-wrapper.') || name.startsWith('cdnca-edge-release-wrapper.')), false)
  return { result, output, calls: existsSync(calls) ? readFileSync(calls, 'utf8').trim().split('\n') : [] }
}

for (const flavor of ['bsd', 'gnu', 'host']) {
  test(`${flavor} stat produces exact integer metadata without failed-probe stdout`, (t) => {
    const { result, output, calls } = runMetadataBuild(t, flavor)
    assert.equal(result.status, 0, result.stderr)
    assert.ok(existsSync(output), result.stderr)
    const metadata = JSON.parse(readFileSync(join(output, 'release-inputs.json'), 'utf8'))
    assert.equal(metadata.schema, 'cdnca.edge.release-build-output/v1')
    assert.equal(metadata.architecture, 'amd64')
    for (const [name, body] of Object.entries(files)) {
      assert.deepEqual(metadata.files[name], { size: Buffer.byteLength(body), sha256: createHash('sha256').update(body).digest('hex') })
    }
    assert.match(metadata.source_manifest_sha256, /^[a-f0-9]{64}$/)
    assert.equal(statSync(join(output, 'release-inputs.json')).mode & 0o777, 0o444)
    assert.deepEqual(calls, flavor === 'host' ? [] : Object.keys(files).flatMap((name) => flavor === 'gnu' ? [`-f:${name}`, `-c:${name}`] : [`-f:${name}`]))
  })
}

for (const target of Object.keys(files)) {
  for (const fault of ['failed-with-output', 'fractional-success']) {
    test(`${target}: ${fault} fails closed without publishing output`, (t) => {
      const { result, output } = runMetadataBuild(t, 'gnu', fault, target)
      assert.notEqual(result.status, 0)
      assert.match(result.stderr, fault === 'failed-with-output' ? /cannot read release file size/ : /invalid release file size/)
      assert.equal(existsSync(output), false)
    })
  }
}

test('omitting metadata preserves the release path without invoking stat', (t) => {
  const { result, output, calls } = runMetadataBuild(t, 'gnu', 'failed-with-output', 'edge-agent', false)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(calls, [])
  assert.equal(existsSync(join(output, 'release-inputs.json')), false)
  for (const [name, body] of Object.entries(files)) assert.equal(readFileSync(join(output, name), 'utf8'), body)
})
