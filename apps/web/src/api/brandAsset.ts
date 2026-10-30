import { ApiError, networkApiError, responseApiError } from './auth'

export type BrandAssetSlot = 'favicon' | 'logo' | 'login_ad' | 'logo_dark' | 'login_background' | 'app_icon'

export interface BrandAsset {
  schema: 'cdnca.platform-brand-asset/v1'
  slot: BrandAssetSlot
  revision: number
  reference?: string
  mime_type?: string
  size_bytes?: number
  sha256?: string
  updated_at?: string
}

export interface BrandAssetListDocument {
  schema: 'cdnca.platform-brand-asset/v1'
  assets: BrandAsset[]
}

export interface BrandAssetUploadMetadata {
  requestId: string
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
// PA-17 added the theme brand slots; the server lists all six.
const slots = new Set<BrandAssetSlot>(['favicon', 'logo', 'login_ad', 'logo_dark', 'login_background', 'app_icon'])
const sha256Pattern = /^[0-9a-f]{64}$/
const mimeTypes = new Set(['image/x-icon', 'image/vnd.microsoft.icon', 'image/png', 'image/jpeg'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isAsset(value: unknown): value is BrandAsset {
  if (!isRecord(value) || value.schema !== 'cdnca.platform-brand-asset/v1' || typeof value.slot !== 'string' || !slots.has(value.slot as BrandAssetSlot) || !Number.isSafeInteger(value.revision) || (value.revision as number) < 0) return false
  for (const key of ['reference', 'mime_type', 'updated_at']) if (key in value && typeof value[key] !== 'string') return false
  if ('size_bytes' in value && (!Number.isSafeInteger(value.size_bytes) || (value.size_bytes as number) < 0)) return false
  if ('sha256' in value && (typeof value.sha256 !== 'string' || !sha256Pattern.test(value.sha256))) return false
  if ('mime_type' in value && !mimeTypes.has(value.mime_type as string)) return false
  if ('updated_at' in value && !Number.isFinite(Date.parse(value.updated_at as string))) return false
  return true
}

function isList(value: unknown): value is BrandAssetListDocument {
  return isRecord(value) && value.schema === 'cdnca.platform-brand-asset/v1' && Array.isArray(value.assets) && value.assets.every(isAsset)
}

async function parse<T>(response: Response, validate: (value: unknown) => value is T): Promise<T> {
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
  if (!validate(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
  return body
}

export const brandAssetApi = {
  async get(accessToken: string, slot: BrandAssetSlot) {
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/brand-assets/${slot}`, { credentials: 'include', headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `brand-asset-${slot}-${crypto.randomUUID()}` } })
    } catch { throw networkApiError() }
    return parse(response, isAsset)
  },
  async list(accessToken: string) {
    let response: Response
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 1000)
    try {
      response = await fetch(`${apiRoot}/v1/admin/brand-assets`, { credentials: 'include', signal: controller.signal, headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `brand-assets-${crypto.randomUUID()}` } })
    } catch { throw networkApiError() } finally { window.clearTimeout(timeout) }
    return parse(response, isList)
  },
  async upload(accessToken: string, slot: BrandAssetSlot, revision: number, file: File, metadata?: BrandAssetUploadMetadata) {
    const identity = metadata ?? (() => {
      const requestId = `brand-asset-${slot}-${crypto.randomUUID()}`
      return { requestId, idempotencyKey: requestId }
    })()
    let response: Response
    try {
      response = await fetch(`${apiRoot}/v1/admin/brand-assets/${slot}`, {
        method: 'PUT', credentials: 'include', body: file,
        headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': identity.requestId, 'Idempotency-Key': identity.idempotencyKey, 'If-Match': `"${revision}"`, 'Content-Type': file.type },
      })
    } catch { throw networkApiError() }
    return parse(response, isAsset)
  },
}
