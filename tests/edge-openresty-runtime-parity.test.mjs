// The node container image (edge/openresty/Dockerfile) and the native node
// package (edge/openresty/native/Dockerfile) must run the same OpenResty: same
// signed tarball, same build base, same ordered patch chain and the same
// configure/make recipe (edge/openresty/native/build-openresty.sh). Lua
// inventory parity is tests/edge-lua-inventory.test.mjs; the built images are
// compared by edge/openresty/runtime-parity-smoke.sh.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(repo, file), 'utf8')
const lock = JSON.parse(read('edge/openresty/native/sources.lock.json'))
const env = Object.fromEntries(read('edge/openresty/runtime.env').trim().split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2)))
const image = read('edge/openresty/Dockerfile')
const native = read('edge/openresty/native/Dockerfile')

// Instructions of the first (builder) stage after its FROM line.
function builderStage(dockerfile) {
  const lines = dockerfile.split('\n')
  const from = lines.findIndex((line) => /^FROM .* AS builder$/.test(line))
  assert.ok(from >= 0, 'no builder stage')
  const body = []
  for (const line of lines.slice(from + 1)) {
    if (/^(FROM|ARG) /.test(line)) break
    if (line.trim() && !line.startsWith('#')) body.push(line)
  }
  return { from: lines[from], body }
}

function argDefault(dockerfile, name) {
  const values = [...dockerfile.matchAll(new RegExp(`^ARG ${name}=(\\S+)$`, 'gm'))].map((match) => match[1])
  assert.ok(values.length > 0, `Dockerfile has no ARG ${name} default`)
  assert.equal(new Set(values).size, 1, `ARG ${name} defaults differ: ${values}`)
  return values[0]
}

test('runtime.env names the locked OpenResty source and build base', () => {
  assert.equal(env.OPENRESTY_VERSION, lock.source.version)
  assert.equal(env.OPENRESTY_TARBALL_URL, lock.source.url)
  assert.equal(env.OPENRESTY_TARBALL_SHA256, lock.source.sha256)
  assert.equal(env.OPENRESTY_BUILD_IMAGE, lock.build_base.reference)
  assert.equal(env.OPENRESTY_SOURCE_DIGEST, env.OPENRESTY_IMAGE.split('@')[1])
  assert.match(env.OPENRESTY_IMAGE, /^openresty\/openresty@sha256:[0-9a-f]{64}$/)
})

test('container image defaults equal runtime.env', () => {
  for (const name of ['OPENRESTY_BUILD_IMAGE', 'OPENRESTY_IMAGE', 'OPENRESTY_VERSION', 'OPENRESTY_SOURCE_DIGEST',
    'OPENRESTY_TARBALL_URL', 'OPENRESTY_TARBALL_SHA256']) {
    assert.equal(argDefault(image, name), env[name], name)
  }
  assert.equal(argDefault(image, 'SOURCE_DATE_EPOCH'), env.OPENRESTY_SOURCE_DATE_EPOCH)
})

test('container and native builder stages are the same recipe on the same base', () => {
  const imageBuilder = builderStage(image)
  const nativeBuilder = builderStage(native)
  assert.equal(nativeBuilder.from, `FROM ${lock.build_base.reference} AS builder`)
  assert.equal(imageBuilder.from, 'FROM ${OPENRESTY_BUILD_IMAGE} AS builder')
  // The container builder may add steps (ipmatcher) only after the shared ones.
  assert.deepEqual(imageBuilder.body.slice(0, nativeBuilder.body.length), nativeBuilder.body)
  assert.ok(nativeBuilder.body.includes('RUN sh /source-contract/build-openresty.sh /source-contract'))
  // The native runtime and the container builder share one base.
  assert.ok(native.includes(`FROM ${lock.build_base.reference} AS runtime\nCOPY --from=builder /usr/local/openresty /usr/local/openresty\n`))
  assert.ok(image.includes('COPY --from=builder /usr/local/openresty /usr/local/openresty\n'))
})

test('no Dockerfile builds OpenResty outside the shared recipe', () => {
  for (const [name, text] of [['container', image], ['native', native]]) {
    assert.ok(!/\.\/configure|\bmake\b|(?:curl|wget)\b[^\n]*\.tar\.gz|\bpatch -|nginx-1\.27/.test(text), `${name} Dockerfile has its own build steps`)
  }
  const recipe = read('edge/openresty/native/build-openresty.sh')
  assert.ok(recipe.includes('node "${contract}/verify-sources.mjs" /tmp/openresty.tar.gz /tmp/openresty-source'))
  assert.ok(recipe.includes('--add-module=/tmp/openresty-source/bundle/cdnca-ja4'))
  assert.ok(recipe.includes('--add-module=/tmp/openresty-source/bundle/ngx_brotli'))
  assert.ok(recipe.includes('--with-stream_realip_module'))
})

test('every patch file is in the lock, in order, and nothing else is applied', () => {
  const onDisk = readdirSync(path.join(repo, 'edge/openresty/native/patches')).filter((file) => file.endsWith('.patch')).sort()
  assert.deepEqual(lock.patches.map((entry) => entry.file.replace(/^patches\//, '')), onDisk)
  assert.deepEqual(onDisk.map((file) => file.slice(0, 2)), onDisk.map((_, index) => String(index + 1).padStart(2, '0')))
  assert.deepEqual([...image.matchAll(/^COPY .*patch.*$/gm)].map((match) => match[0]), ['COPY edge/openresty/native/patches /source-contract/patches'],
    'container image copies extra patches')
})

test('the container image checks its OpenResty against the lock at build time', () => {
  for (const fragment of [
    'test "${actual_version}" = "${OPENRESTY_VERSION}"',
    'verified.patches == #lock.patches',
    'lock.build_base.reference == [[${OPENRESTY_BUILD_IMAGE}]]',
    '--add-module=/tmp/openresty-source/bundle/cdnca-ja4',
    '--add-module=/tmp/openresty-source/bundle/ngx_brotli',
    'proxy_toa on;',
    '--add-module=/tmp/openresty-source/bundle/ngx_brotli; do',
    'brotli on; brotli_comp_level $cookie_l; gzip_comp_level $cookie_l;',
  ]) assert.ok(image.includes(fragment), fragment)
})

// h3probe (the Agent's HTTP/3 health probe) ships in both: the same stage,
// from the committed client module, on the Go builder pinned in versions.env.
function h3probeStage(dockerfile) {
  const lines = dockerfile.split('\n')
  const from = lines.findIndex((line) => / AS h3probe$/.test(line))
  assert.ok(from >= 0, 'no h3probe stage')
  const body = []
  for (const line of lines.slice(from + 1)) {
    if (/^FROM /.test(line)) break
    if (line.trim() && !line.startsWith('#')) body.push(line)
  }
  return { from: lines[from], body }
}

test('container image and native package build the same static h3probe', () => {
  const versions = Object.fromEntries(read('edge/openresty/http3/versions.env').trim().split('\n').map((line) => line.split(/=(.*)/s).slice(0, 2)))
  const nativeStage = h3probeStage(native), imageStage = h3probeStage(image)
  assert.equal(nativeStage.from, `FROM ${versions.HTTP3_CLIENT_BUILDER} AS h3probe`)
  assert.deepEqual(imageStage, nativeStage)
  assert.ok(nativeStage.body.includes('ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=readonly GOPROXY=${GOPROXY}'))
  for (const source of ['client.mod /h3probe-src/go.mod', 'client.sum /h3probe-src/go.sum', 'main.go /h3probe-src/main.go']) {
    assert.ok(nativeStage.body.includes(`COPY edge/openresty/http3/client/${source}`), source)
  }
  assert.ok(nativeStage.body.some((line) => line.includes("go build -trimpath -ldflags '-s -w -buildid=' -o /out/h3probe .") && line.includes('/out/h3probe version')))
  assert.equal(read('edge/openresty/http3/client/Dockerfile').split('\n')[0], `FROM ${versions.HTTP3_CLIENT_BUILDER} AS build`)
  // The image puts it where edge-http3-smoke and a container Agent look for it, and proves it runs.
  assert.ok(image.includes('COPY --from=h3probe --chmod=0555 /out/h3probe /usr/local/bin/h3probe\n'))
  assert.ok(image.includes('/usr/local/bin/h3probe version | grep -F \'"schema":"cdnca.h3probe/v1"\''))
})
