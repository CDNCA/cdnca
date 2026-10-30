// node --test docs/developer/examples/plugin-ui-sdk/sdk.test.mjs
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import { connect, PROTOCOL, readNonce } from './cdnca-plugin-ui.mjs'
import { createVerifier } from './verify-backend.mjs'

const vector = JSON.parse(readFileSync(new URL('./proxy-vector.json', import.meta.url), 'utf8'))

// A fake frame window whose parent behaves like the cdnca host bridge.
function fakeFrame(nonce, answer) {
  const listeners = new Set()
  const frame = {
    location: { hash: `#cdnca-nonce=${nonce}` },
    addEventListener: (type, fn) => listeners.add(fn),
    removeEventListener: (type, fn) => listeners.delete(fn),
  }
  const parent = {
    postMessage(data) {
      assert.deepEqual(data, { protocol: PROTOCOL, type: 'cdnca.hello', nonce })
      const channel = new MessageChannel()
      channel.port1.onmessage = (event) => channel.port1.postMessage(answer(event.data))
      // A foreign window's ready is ignored, then the parent's is taken.
      for (const fn of [...listeners]) fn({ source: {}, data: { protocol: PROTOCOL, type: 'cdnca.ready', nonce }, ports: [new MessageChannel().port2] })
      for (const fn of [...listeners]) fn({ source: parent, data: { protocol: PROTOCOL, type: 'cdnca.ready', nonce }, ports: [channel.port2] })
    },
  }
  frame.parent = parent
  return frame
}

test('reads the mount nonce from the fragment only', () => {
  assert.equal(readNonce('#cdnca-nonce=abcdefghijklmnop'), 'abcdefghijklmnop')
  assert.throws(() => readNonce('#other=1'), { code: 'nonce_missing' })
})

test('handshake, context, api.request and refused methods', async () => {
  const nonce = 'n0nce-n0nce-n0nce-1'
  const seen = []
  const frame = fakeFrame(nonce, (request) => {
    seen.push(request)
    const reply = { protocol: PROTOCOL, nonce, id: request.id }
    if (request.method === 'context.get') return { ...reply, ok: true, result: { plugin_id: 'acme.reports', locale: 'zh-CN' } }
    if (request.method === 'api.request') return { ...reply, ok: true, result: { status: 200, body: { rows: 3 } } }
    return { ...reply, ok: false, error: 'navigate_path_not_allowed' }
  })
  const host = await connect({ window: frame, timeoutMs: 1000 })
  assert.deepEqual(await host.context(), { plugin_id: 'acme.reports', locale: 'zh-CN' })
  assert.deepEqual(await host.request({ method: 'GET', path: '/reports', query: 'range=7d' }), { status: 200, body: { rows: 3 } })
  await assert.rejects(host.navigate('/login'), { code: 'navigate_path_not_allowed' })
  assert.deepEqual(seen.map((item) => item.method), ['context.get', 'api.request', 'navigate'])
  assert.ok(seen.every((item) => item.protocol === PROTOCOL && item.nonce === nonce))
  host.close()
})

test('backend verifier accepts the control plane vector once and rejects tampering', () => {
  const now = () => Date.parse(vector.now)
  const make = () => createVerifier({ publicKey: vector.public_key, keyId: vector.key_id, basePath: vector.api_base_path, now })
  const call = (overrides = {}) => ({ method: vector.method, pathWithQuery: vector.path_with_query,
    body: Buffer.from(vector.body), headers: { ...vector.headers }, ...overrides })
  const verifier = make()
  const context = verifier.verify(call())
  assert.equal(context.plugin_id, 'acme.reports')
  assert.equal(context.role, 'admin')
  assert.throws(() => verifier.verify(call()), /replayed nonce/)
  assert.throws(() => make().verify(call({ body: Buffer.from('{"range":"30d"}') })), /bad signature/)
  assert.throws(() => make().verify(call({ pathWithQuery: '/v1/reports/run?site=2' })), /bad signature/)
  assert.throws(() => make().verify(call({ headers: { ...vector.headers, 'X-Cdnca-Plugin-Key-Id': '0000000000000000' } })), /unknown key id/)
  const late = createVerifier({ publicKey: vector.public_key, keyId: vector.key_id, basePath: '/v1', now: () => now() + 120000 })
  assert.throws(() => late.verify(call()), /context expired/)
})
