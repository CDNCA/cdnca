import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const originPattern = /^https:\/\/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/

// PluginUIPage is one page of an enabled ui_page plugin (GET /v1/plugin-ui/pages,
// PA-19): already filtered by the server for this principal's role,
// permissions and granted modules.
export interface PluginUIPage {
  plugin_id: string
  plugin_version: string
  page_id: string
  origin: string
  url: string
  mount: 'menu' | 'site_tab'
  menu_parent?: string
  role: 'admin' | 'user'
  title: { 'zh-CN': string; 'en-US'?: string }
  required_permission?: string
  required_module?: string
  has_api: boolean
}

function validPage(value: unknown): value is PluginUIPage {
  if (typeof value !== 'object' || value === null) return false
  const page = value as Record<string, unknown>
  const title = page.title as Record<string, unknown> | undefined
  return typeof page.plugin_id === 'string' && typeof page.page_id === 'string' &&
    typeof page.origin === 'string' && originPattern.test(page.origin) &&
    typeof page.url === 'string' && page.url.startsWith(`${page.origin}/`) &&
    (page.mount === 'menu' || page.mount === 'site_tab') && (page.role === 'admin' || page.role === 'user') &&
    typeof title?.['zh-CN'] === 'string' && typeof page.has_api === 'boolean'
}

export async function fetchPluginUIPages(token: string): Promise<PluginUIPage[]> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/plugin-ui/pages`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = (await response.json().catch(() => undefined)) as { items?: unknown } | undefined
  if (!body || !Array.isArray(body.items) || !body.items.every(validPage)) {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
  return body.items
}

export interface PluginProxyRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  query?: string
  body?: unknown
  page_id: string
  site_id?: string
}

/** pluginProxy calls the plugin backend through the control plane (the
 * session token stays here; the plugin backend gets a signed context). */
export async function pluginProxy(token: string, pluginID: string, request: PluginProxyRequest): Promise<{ status: number; body: unknown }> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/plugin-ui/${encodeURIComponent(pluginID)}/proxy`, {
      method: 'POST',
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = (await response.json().catch(() => undefined)) as { status?: unknown; body?: unknown } | undefined
  if (!body || typeof body.status !== 'number') throw new ApiError('Invalid response', 502, 'response_invalid')
  return { status: body.status, body: body.body ?? null }
}

// PluginUISigningKey is the installation public key a ui_page plugin backend
// verifies proxied calls with (GET /v1/plugin-ui/signing-key; public material only).
export interface PluginUISigningKey {
  installation_id: string
  key_id: string
  algorithm: 'Ed25519'
  public_key: string
  signature_domain: string
}

export async function fetchPluginUISigningKey(token: string): Promise<PluginUISigningKey> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/plugin-ui/signing-key`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = (await response.json().catch(() => undefined)) as Partial<PluginUISigningKey> | undefined
  if (!body || body.algorithm !== 'Ed25519' || typeof body.installation_id !== 'string' ||
    typeof body.key_id !== 'string' || !/^[0-9a-f]{16}$/.test(body.key_id) ||
    typeof body.public_key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.public_key) ||
    typeof body.signature_domain !== 'string') {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
  return body as PluginUISigningKey
}
