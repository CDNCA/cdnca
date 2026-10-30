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
// three methods (anything else: error "message_not_allowed").

export const PROTOCOL = 'cdnca.plugin-ui/v1'

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
    if (!data || data.protocol !== PROTOCOL || data.nonce !== nonce || !pending.has(data.id)) return
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
      const timer = setTimeout(() => {
        pending.delete(id)
        reject(new PluginUIError('request_timeout'))
      }, requestTimeoutMs)
      pending.set(id, { resolve, reject, timer })
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
