// cdnca ui_page plugin SDK (inside the frame), protocol cdnca.plugin-ui/v1.
// See docs/developer/plugin-integration.md §8.3. No dependencies; serve it
// from your own page origin and load it as an ES module:
//
//   import { connect } from './cdnca-plugin-ui.mjs'
//   const host = await connect()
//   const ctx = await host.context()           // user / tenant / site / locale / theme, no credentials
//   const res = await host.request({ method: 'GET', path: '/reports', query: 'range=7d' })
//   // res = { status, body }: your backend's answer, relayed by the control plane
//   await host.navigate('/site/list')          // in-app path; auth pages are refused
//
// The page runs in <iframe sandbox="allow-scripts allow-forms"> (opaque
// origin): no cookies or storage of the control plane, and no
// credentials of the user. Everything goes through one private MessagePort
// the host hands over after "cdnca.hello"; the host answers only these
// methods (anything else: error "message_not_allowed"). identity.* take no
// parameters: the host decides the permissions (manifest ∩ the user's) and
// your backend receives the credential at PUT {api_base_url}/plugin-identity
// (signed context with delivery "plugin_identity"); a cancelled dialog is
// error "identity_cancelled".
//
// requestTimeoutMs bounds the network time of a call, not the time the user
// spends reading the host's confirmation: while the dialog of an
// identity.authorize / identity.revoke is open the host sends
// { type: "cdnca.waiting", request_id, waiting: true } (and waiting: false
// once the user answered), and the call's timer stops until then. The message
// carries no "id", so an older SDK ignores it; an older host never sends it
// and the timer runs as before.

export const PROTOCOL = 'cdnca.plugin-ui/v1'

// The calls during which the host may wait for the user (its confirmation dialog).
const PAUSABLE = new Set(['identity.authorize', 'identity.revoke'])

export class PluginUIError extends Error {
  constructor(code) {
    super(code)
    this.name = 'PluginUIError'
    this.code = code
  }
}

/** The mount nonce the host put in the URL fragment (#cdnca-nonce=...). */
export function readNonce(hash = globalThis.location?.hash ?? '') {
  const value = new URLSearchParams(String(hash).replace(/^#/, '')).get('cdnca-nonce')
  if (!value || !/^[A-Za-z0-9_-]{16,64}$/.test(value)) throw new PluginUIError('nonce_missing')
  return value
}

/**
 * connect performs the hello handshake and resolves to the host API.
 * options: { window, timeoutMs, requestTimeoutMs } (window for tests).
 */
export function connect(options = {}) {
  const win = options.window ?? globalThis.window
  const timeoutMs = options.timeoutMs ?? 10000
  const requestTimeoutMs = options.requestTimeoutMs ?? 30000
  const nonce = readNonce(win.location.hash)
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      win.removeEventListener('message', onReady)
      reject(new PluginUIError('handshake_timeout'))
    }, timeoutMs)
    function onReady(event) {
      // Only the parent (the control plane web app) hands over the port.
      const data = event.data
      if (event.source !== win.parent || !data || data.protocol !== PROTOCOL || data.type !== 'cdnca.ready' ||
        data.nonce !== nonce || !event.ports || event.ports.length !== 1) return
      clearTimeout(timer)
      win.removeEventListener('message', onReady)
      resolve(createHost(event.ports[0], nonce, requestTimeoutMs))
    }
    win.addEventListener('message', onReady)
    // The host's origin is the control plane domain the customer runs; the
    // hello carries nothing secret, the port it answers with is private.
    win.parent.postMessage({ protocol: PROTOCOL, type: 'cdnca.hello', nonce }, '*')
  })
}

function createHost(port, nonce, requestTimeoutMs) {
  const pending = new Map()
  let sequence = 0
  port.onmessage = (event) => {
    const data = event.data
    if (!data || data.protocol !== PROTOCOL || data.nonce !== nonce) return
    if (data.type === 'cdnca.waiting') {
      // The host waits for the user's answer in its own dialog: that is not network time. The timer stops and
      // starts again in full once the user answered (the write that follows is network time).
      const entry = pending.get(data.request_id)
      if (!entry || !PAUSABLE.has(entry.method) || typeof data.waiting !== 'boolean') return
      clearTimeout(entry.timer)
      entry.timer = data.waiting ? undefined : setTimeout(entry.expire, requestTimeoutMs)
      return
    }
    if (!pending.has(data.id)) return
    const { resolve, reject, timer } = pending.get(data.id)
    pending.delete(data.id)
    clearTimeout(timer)
    if (data.ok) resolve(data.result)
    else reject(new PluginUIError(typeof data.error === 'string' ? data.error : 'request_failed'))
  }
  port.start?.()
  function call(method, params) {
    const id = `r${++sequence}`
    return new Promise((resolve, reject) => {
      const expire = () => {
        pending.delete(id)
        reject(new PluginUIError('request_timeout'))
      }
      pending.set(id, { method, resolve, reject, expire, timer: setTimeout(expire, requestTimeoutMs) })
      port.postMessage({ protocol: PROTOCOL, nonce, id, method, ...(params === undefined ? {} : { params }) })
    })
  }
  return {
    /** Non-sensitive context: { plugin_id, page_id, user, tenant, site_id, locale, theme }. */
    context: () => call('context.get'),
    /** Move the host to an in-app relative path. */
    navigate: (path) => call('navigate', { path }),
    /**
     * Call your own backend (api_base_url + path) through the control plane.
     * request: { method: GET|POST|PUT|PATCH|DELETE, path: '/x', query?: 'a=1', body?: JSON (not with GET) }.
     */
    request: (request) => call('api.request', request),
    close: () => port.close(),
  }
}
