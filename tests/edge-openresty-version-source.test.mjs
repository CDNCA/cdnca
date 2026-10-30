// The node OpenResty release has one source: edge/openresty/runtime.env
// (equal to native/sources.lock.json, see edge-openresty-runtime-parity). The
// HTTP/3 runtime pin in Go is held to it by
// agents/edge-agent/internal/http3runtime/runtime_version_contract_test.go;
// this test holds the smoke and E2E drivers to it, so a runtime upgrade
// cannot leave a driver asserting the previous release.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(repo, file), 'utf8')
const env = Object.fromEntries(read('edge/openresty/runtime.env').trim().split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2)))

// An OpenResty release literal: openresty/1.2.3.4, openresty:1.2.3.4-...,
// "openresty_version": "1.2.3.4", OPENRESTY_VERSION=1.2.3.4, ...
// 后面紧跟 ':端口' 的是地址（"OpenResty on 0.0.0.0:18080"、"OpenResty ${IMAGE}) 127.0.0.1:${PORT}"），不是版本。
const releaseLiteral = /openresty[^0-9\n]{0,40}\d+\.\d+\.\d+\.\d+(?![\d.]*:)/gi
// Historical evidence deliberately kept for the release it was taken for.
const historical = new Set([
  'edge/openresty/security-release/advisory-snapshot.json',
  'tests/edge-runtime-security-release-e2e/run.sh',
  // 这两处 OpenResty 扮演第三方 CDN（GW-03 网关经 CDN 回源），不是节点运行时，镜像独立于 runtime.env。
  'tests/gateway-cdn-e2e/run.sh',
  'tests/gateway-cdn-poc/run.sh',
])

test('runtime.env pins one OpenResty release and image', () => {
  assert.match(env.OPENRESTY_VERSION, /^\d+\.\d+\.\d+\.\d+$/)
  assert.match(env.OPENRESTY_IMAGE, /^openresty\/openresty@sha256:[0-9a-f]{64}$/)
})

test('the HTTP/3 smoke asserts the runtime.env release, exactly', () => {
  const smoke = read('scripts/edge-http3-smoke.sh')
  assert.ok(smoke.includes('. "${repo_root}/edge/openresty/runtime.env"\n'))
  assert.ok(smoke.includes('grep -Fx "nginx version: openresty/${OPENRESTY_VERSION}" "${workdir}/runtime-version.txt" >/dev/null\n'))
})

test('edge-site smokes default to the runtime.env image', () => {
  for (const [file, variable] of [['tests/edge-site/dns-origin-smoke.sh', 'CDNCA_SITE_DNS_SMOKE_IMAGE']]) {
    const script = read(file)
    const source = script.indexOf('. "$repo_root/edge/openresty/runtime.env"\n')
    const image = script.indexOf(`image=\${${variable}:-$OPENRESTY_IMAGE}\n`)
    assert.ok(source >= 0 && image > source, `${file} does not take its OpenResty image from runtime.env`)
  }
})

test('no smoke, E2E or runtime input pins another OpenResty release', () => {
  const files = execFileSync('git', ['-C', repo, 'ls-files', '-z', '--', 'scripts', 'tests', 'edge', 'deploy', 'agents'], { encoding: 'utf8' })
    .split('\0')
    .filter((file) => /(\.sh|\.json|\.env|\.conf|\.ya?ml|Dockerfile[^/]*)$/.test(file) && !historical.has(file))
  const stale = []
  for (const file of files) {
    for (const match of read(file).matchAll(releaseLiteral)) {
      if (!match[0].endsWith(env.OPENRESTY_VERSION)) stale.push(`${file}: ${match[0]}`)
    }
  }
  assert.deepEqual(stale, [])
})
