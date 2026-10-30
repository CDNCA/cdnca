// Host side of the ui_page plugin postMessage protocol (PA-19, ADR 0007 §8.3).
//
// The page runs in <iframe sandbox="allow-scripts allow-forms"> without
// allow-same-origin, so its origin is opaque ("null"): it cannot read this
// app's cookies, localStorage, sessionStorage or IndexedDB, and it cannot
// reach the DOM of the host. The host therefore identifies it by
// event.source === iframe.contentWindow plus a per-mount nonce, never by
// event.origin. After the page's "cdnca.hello" the host hands it a private
// MessagePort; every later message travels on that port only.
//
// Whitelist (anything else is answered with error "message_not_allowed"):
//   context.get   non-sensitive user / tenant / site context (no token)
//   navigate      move the host to an allowed in-app path
//   api.request   call the plugin's own backend through the control plane
//                 proxy (POST /v1/plugin-ui/{plugin}/proxy)

export const protocolVersion = 'cdnca.plugin-ui/v1'

export type BridgeMethod = 'context.get' | 'navigate' | 'api.request'
export const allowedMethods: readonly BridgeMethod[] = ['context.get', 'navigate', 'api.request']

export interface PluginUIContext {
  protocol: string
  plugin_id: string
  page_id: string
  user: { id: string; display_name: string; role: 'admin' | 'user' }
  tenant: { scope_id: string; scope_kind: 'platform' | 'tenant' }
  site_id: string | null
  locale: string
  theme: 'light' | 'dark'
}

export interface ApiRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  query?: string
  body?: unknown
}

export interface BridgeHost {
  context: () => PluginUIContext
  navigate: (path: string) => void
  apiRequest: (request: ApiRequest) => Promise<{ status: number; body: unknown }>
}

export interface BridgeRequest {
  protocol: string
  nonce: string
  id: string
  method: string
  params?: unknown
}

export interface BridgeResponse {
  protocol: string
  nonce: string
  id: string
  ok: boolean
  result?: unknown
  error?: string
}

const idPattern = /^[A-Za-z0-9._:-]{1,64}$/
const navigatePattern = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}(\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,512})?$/
const apiPathPattern = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,511}$/
const apiQueryPattern = /^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,1024}$/
const apiMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
// In-app paths a plugin page may send the user to (never login, account
// security, API keys or other auth flows).
const navigateDenied = /^\/(login|register|forget-password|forgot-password|reset-password|account\/api|account\/user)(\/|$|\?)/

/** A fresh mount nonce (128 random bits, base64url). */
export function newNonce(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  let text = ''
  for (const value of bytes) text += String.fromCharCode(value)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** validNavigatePath: a relative in-app path, no scheme, no "//", no dot segments. */
export function validNavigatePath(path: unknown): path is string {
  if (typeof path !== 'string' || !navigatePattern.test(path) || navigateDenied.test(path)) return false
  return !path.split('?')[0].split('/').some((segment) => segment === '.' || segment === '..')
}

export function validApiRequest(params: unknown): params is ApiRequest {
  if (!isRecord(params)) return false
  const keys = Object.keys(params)
  if (keys.some((key) => !['method', 'path', 'query', 'body'].includes(key))) return false
  const { method, path, query, body } = params
  if (typeof method !== 'string' || !apiMethods.has(method) || typeof path !== 'string' || !apiPathPattern.test(path) ||
    path.split('/').some((segment) => segment === '.' || segment === '..')) return false
  if (query !== undefined && (typeof query !== 'string' || !apiQueryPattern.test(query))) return false
  if (body !== undefined && method === 'GET') return false
  if (body !== undefined) {
    try {
      if (JSON.stringify(body).length > 256 * 1024) return false
    } catch {
      return false
    }
  }
  return true
}

/**
 * handleBridgeRequest answers one message that arrived on the private port.
 * It never throws; a message that is not a well-formed request for this
 * mount (wrong protocol / nonce / id) gets no answer at all.
 */
export async function handleBridgeRequest(nonce: string, data: unknown, host: BridgeHost): Promise<BridgeResponse | null> {
  if (!isRecord(data) || data.protocol !== protocolVersion || data.nonce !== nonce ||
    typeof data.id !== 'string' || !idPattern.test(data.id) || typeof data.method !== 'string') {
    return null
  }
  const reply = (ok: boolean, payload: { result?: unknown; error?: string }): BridgeResponse => ({
    protocol: protocolVersion, nonce, id: data.id as string, ok, ...payload,
  })
  switch (data.method) {
    case 'context.get':
      return reply(true, { result: host.context() })
    case 'navigate': {
      const path = isRecord(data.params) ? data.params.path : undefined
      if (!validNavigatePath(path)) return reply(false, { error: 'navigate_path_not_allowed' })
      host.navigate(path)
      return reply(true, { result: null })
    }
    case 'api.request': {
      if (!validApiRequest(data.params)) return reply(false, { error: 'api_request_invalid' })
      try {
        return reply(true, { result: await host.apiRequest(data.params) })
      } catch (error) {
        const code = isRecord(error) && typeof error.code === 'string' ? error.code : 'api_request_failed'
        return reply(false, { error: code })
      }
    }
    default:
      return reply(false, { error: 'message_not_allowed' })
  }
}

/** isHello: the page's first message, sent to the host window. */
export function isHello(data: unknown, nonce: string): boolean {
  return isRecord(data) && data.protocol === protocolVersion && data.type === 'cdnca.hello' && data.nonce === nonce
}

/** The sandbox token list the host mounts every plugin page with. */
export const sandboxTokens = ['allow-scripts', 'allow-forms'] as const

/** frameURL appends the mount nonce as a fragment (not sent to the server). */
export function frameURL(url: string, nonce: string): string {
  return `${url}#cdnca-nonce=${encodeURIComponent(nonce)}`
}
