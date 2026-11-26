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

// A frame whose parent hands over a port the test drives by hand: requests are recorded, host messages are
// delivered synchronously (deterministic with mocked timers).
function manualFrame(nonce) {
  const listeners = new Set()
  const requests = []
  const port = { postMessage: (data) => requests.push(data), start() {}, close() {} }
  const parent = {
    postMessage() {
      for (const fn of [...listeners]) fn({ source: parent, data: { protocol: PROTOCOL, type: 'cdnca.ready', nonce }, ports: [port] })
    },
  }
  const frame = {
    location: { hash: `#cdnca-nonce=${nonce}` }, parent,
    addEventListener: (type, fn) => listeners.add(fn),
    removeEventListener: (type, fn) => listeners.delete(fn),
  }
  const send = (data) => port.onmessage({ data: { protocol: PROTOCOL, nonce, ...data } })
  return {
    frame, requests,
    waiting: (id, waiting) => send({ type: 'cdnca.waiting', request_id: id, waiting }),
    answer: (id, ok, value) => send(ok ? { id, ok: true, result: value } : { id, ok: false, error: value }),
  }
}

// Settles a promise into a readable outcome without awaiting it.
function track(promise) {
  const outcome = { state: 'pending' }
  promise.then((value) => Object.assign(outcome, { state: 'ok', value }), (error) => Object.assign(outcome, { state: 'error', code: error.code }))
  return outcome
}
const flush = () => new Promise((resolve) => setImmediate(resolve))

test('the time the user reads the host confirmation (45 s, 90 s) is not counted, then confirm or cancel', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  for (const method of ['authorize', 'revoke']) {
    for (const wait of [45000, 90000]) {
      for (const confirm of [true, false]) {
        const step = `${method} after ${wait / 1000} s, ${confirm ? 'confirmed' : 'cancelled'}`
        const nonce = 'n0nce-n0nce-n0nce-3'
        const io = manualFrame(nonce)
        const host = await connect({ window: io.frame, timeoutMs: 1000, requestTimeoutMs: 30000 })
        const outcome = track(host.identity[method]())
        const { id } = io.requests.at(-1)
        t.mock.timers.tick(1000) // the host's GET of the status
        io.waiting(id, true)
        t.mock.timers.tick(wait)
        await flush()
        assert.equal(outcome.state, 'pending', step)
        io.waiting(id, false)
        t.mock.timers.tick(500) // the write (or the cancel answer)
        if (confirm) io.answer(id, true, { identity: method === 'revoke' ? null : { key_id: 'cfk_x' } })
        else io.answer(id, false, 'identity_cancelled')
        await flush()
        assert.deepEqual(outcome, confirm ? { state: 'ok', value: { identity: method === 'revoke' ? null : { key_id: 'cfk_x' } } }
          : { state: 'error', code: 'identity_cancelled' }, step)
        assert.equal(io.requests.length, 1, step)
        host.close()
      }
    }
  }
})

test('network time stays bounded: a slow status read, a slow write after the answer, and a late reply', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const io = manualFrame('n0nce-n0nce-n0nce-4')
  const host = await connect({ window: io.frame, timeoutMs: 1000, requestTimeoutMs: 30000 })

  // No waiting message (an older host, or the GET before the dialog never answers): 30 s as before.
  const slowRead = track(host.identity.revoke())
  t.mock.timers.tick(30000)
  await flush()
  assert.deepEqual(slowRead, { state: 'error', code: 'request_timeout' })

  // The user answered; the write then takes longer than the request timeout: the timer started again in full.
  const slowWrite = track(host.identity.authorize())
  const { id } = io.requests.at(-1)
  io.waiting(id, true)
  t.mock.timers.tick(120000)
  io.waiting(id, false)
  t.mock.timers.tick(29999)
  await flush()
  assert.equal(slowWrite.state, 'pending')
  t.mock.timers.tick(1)
  await flush()
  assert.deepEqual(slowWrite, { state: 'error', code: 'request_timeout' })
  io.answer(id, true, { identity: null }) // late: nobody waits for it any more, nothing throws
  await flush()
  assert.deepEqual(slowWrite, { state: 'error', code: 'request_timeout' })
  host.close()
})

test('a waiting message pauses only its own identity write: other calls, repeated clicks and old shapes keep the timer', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] })
  const io = manualFrame('n0nce-n0nce-n0nce-5')
  const host = await connect({ window: io.frame, timeoutMs: 1000, requestTimeoutMs: 30000 })
  const first = track(host.identity.revoke())
  const second = track(host.identity.revoke()) // a repeated click: its own request and its own timer
  const api = track(host.request({ method: 'GET', path: '/state' }))
  const [firstID, secondID, apiID] = io.requests.map((request) => request.id)
  io.waiting(firstID, true)
  io.waiting(apiID, true) // not a call the host asks the user about: ignored
  io.waiting(secondID, 'yes') // malformed: ignored
  io.waiting('r999', true) // unknown request: ignored
  t.mock.timers.tick(30000)
  await flush()
  assert.equal(first.state, 'pending')
  assert.deepEqual(second, { state: 'error', code: 'request_timeout' })
  assert.deepEqual(api, { state: 'error', code: 'request_timeout' })
  io.waiting(firstID, false)
  io.answer(firstID, true, { identity: null })
  await flush()
  assert.deepEqual(first, { state: 'ok', value: { identity: null } })
  host.close()
})
