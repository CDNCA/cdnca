// The container image (edge/openresty/Dockerfile) and the native node package
// must ship the same CDNCA Lua modules: the agent renders the same
// require(...) calls for both. Each image file must also be pinned by sha256
// in the Dockerfile and checked again by the entrypoint.
//
// Not compared here: resty/ipmatcher.lua, which both images install into
// OpenResty's lualib (container: downloaded at the pinned commit; native:
// vendored copy of the same file, edge/openresty/vendor/lua-resty-ipmatcher,
// checked by the next test).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { luaSources } from '../scripts/native-node-runtime-acceptance.mjs'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(repo, file), 'utf8')
const sha256 = (file) => createHash('sha256').update(readFileSync(path.join(repo, file))).digest('hex')

// Image path -> native package member.
function packageMember(target) {
  if (target.startsWith('/usr/local/share/cdnca/')) return `lua/share/cdnca/${target.slice('/usr/local/share/cdnca/'.length)}`
  if (target.startsWith('/opt/cdnca/l4geo/')) return `lua/l4geo/${target.slice('/opt/cdnca/l4geo/'.length)}`
  return null
}

function luaCopies(dockerfile) {
  const copies = new Map()
  for (const line of read(dockerfile).split('\n')) {
    const match = /^COPY (?:--chmod=\S+ )?(edge\/openresty\/\S+\.lua) (\/\S+)$/.exec(line)
    if (match && packageMember(match[2])) copies.set(packageMember(match[2]), { source: match[1], target: match[2] })
  }
  return copies
}

function packageRequired() {
  const block = /const required = \[([\s\S]*?)\]/.exec(read('scripts/native-node-package.mjs'))
  return [...block[1].matchAll(/'(lua\/[^']+)'/g)].map((match) => match[1]).sort()
}

const image = luaCopies('edge/openresty/Dockerfile')
const native = luaCopies('edge/openresty/native/Dockerfile')

test('container image and native package ship the same Lua modules', () => {
  assert.ok(!image.has(null), 'container image copies Lua outside the CDNCA Lua roots')
  assert.deepEqual([...image.keys()].sort(), [...native.keys()].sort(), 'container image vs native Dockerfile')
  assert.deepEqual([...image.keys()].sort(), packageRequired(), 'container image vs native package required members')
  assert.deepEqual([...image.keys()].sort(), Object.keys(luaSources).sort(), 'container image vs native acceptance luaSources')
})

test('both images take each Lua module from the same source file', () => {
  for (const [member, copy] of image) {
    assert.equal(copy.source, native.get(member).source, member)
    assert.equal(copy.source, luaSources[member], member)
  }
})

test('every container image Lua module is pinned in the Dockerfile and the entrypoint', () => {
  const dockerfile = read('edge/openresty/Dockerfile')
  const entrypoint = read('edge/openresty/entrypoint.sh')
  for (const { source, target } of image.values()) {
    const digest = sha256(source)
    // Either echo '<digest>  <path>' or printf '%s  %s\n' <digest> <path>.
    assert.ok(new RegExp(`${digest}\\s+${target.replaceAll('/', '\\/').replaceAll('.', '\\.')}[' ]`).test(dockerfile),
      `Dockerfile build check misses ${target} at ${digest}`)
    const variable = [...entrypoint.matchAll(/^(\w+_sha256)="([a-f0-9]{64})"$/gm)].find((match) => match[2] === digest)
    assert.ok(variable, `entrypoint pins no ${source} at ${digest}`)
    assert.ok(entrypoint.includes(`"\${${variable[1]}}" ${target} | sha256sum -c -`), `entrypoint does not check ${target}`)
  }
})

// The native image ships the firewall action engine's resty.ipmatcher at the
// container image's pin (it was missing: every firewall action site 503).
test('native image ships resty.ipmatcher at the container pin', () => {
  const pin = /ARG IPMATCHER_SHA256=([0-9a-f]{64})/.exec(read('edge/openresty/Dockerfile'))[1]
  assert.equal(sha256('edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua'), pin)
  const native = read('edge/openresty/native/Dockerfile')
  assert.match(native, /^COPY edge\/openresty\/vendor\/lua-resty-ipmatcher\/ipmatcher\.lua \/source-contract\/vendor\/ipmatcher\.lua$/m)
  assert.match(native, /^COPY --from=builder \/source-contract\/vendor\/ipmatcher\.lua \/usr\/local\/openresty\/lualib\/resty\/ipmatcher\.lua$/m)
  assert.ok(packageRequiredAll().includes('runtime/openresty/lualib/resty/ipmatcher.lua'))
})

function packageRequiredAll() {
  const block = /const required = \[([\s\S]*?)\]/.exec(read('scripts/native-node-package.mjs'))
  return [...block[1].matchAll(/'([^']+)'/g)].map((match) => match[1])
}
