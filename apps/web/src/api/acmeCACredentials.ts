import { ApiError, networkApiError, responseApiError } from './auth'

// ACME External Account Binding credentials of the CAs that require them.
// The HMAC key is write-only: reads show only whether one is
// set and the first 8 hex digits of its SHA-256.
export type AcmeEABCA = 'zerossl' | 'google_trust'

export interface AcmeCACredential {
  ca: AcmeEABCA
  directory_url: string
  configured: boolean
  eab_key_id?: string
  eab_hmac_sha256_prefix?: string
  revision: number
  updated_at?: string
}

export type AcmeCACredentialWrite =
  | { expected_revision: number; eab_key_id: string; eab_hmac_key: string }
  | { expected_revision: number; clear: true }

// 按 ZeroSSL 邮箱自动获取 EAB 并保存（HMAC 不回传）。
export interface ZeroSSLEABEmailRequest { expected_revision: number; email: string }

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function isCredential(value: unknown): value is AcmeCACredential {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const item = value as Record<string, unknown>
  return (item.ca === 'zerossl' || item.ca === 'google_trust') && typeof item.directory_url === 'string' &&
    item.directory_url.startsWith('https://') && typeof item.configured === 'boolean' &&
    Number.isSafeInteger(item.revision) && Number(item.revision) >= 0 &&
    (item.eab_key_id === undefined || typeof item.eab_key_id === 'string') &&
    (item.eab_hmac_sha256_prefix === undefined || (typeof item.eab_hmac_sha256_prefix === 'string' && /^[0-9a-f]{8}$/.test(item.eab_hmac_sha256_prefix))) &&
    !('eab_hmac_key' in item)
}

async function call(accessToken: string, method: 'GET' | 'PUT' | 'POST', path: string, body?: AcmeCACredentialWrite | ZeroSSLEABEmailRequest): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      method, credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}`, 'X-Request-ID': `acme-ca-credentials-${crypto.randomUUID()}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
  } catch { throw networkApiError() }
  if (!response.ok) throw await responseApiError(response)
  try { return await response.json() } catch { throw new ApiError('Invalid API response', 0, 'invalid_response') }
}

export const acmeCACredentialsApi = {
  async list(accessToken: string): Promise<AcmeCACredential[]> {
    const body = await call(accessToken, 'GET', '/v1/admin/acme-ca-credentials')
    const items = (body as { items?: unknown })?.items
    if (!Array.isArray(items) || !items.every(isCredential)) throw new ApiError('Invalid API response', 0, 'invalid_response')
    return items
  },
  async save(accessToken: string, ca: AcmeEABCA, write: AcmeCACredentialWrite): Promise<AcmeCACredential> {
    const body = await call(accessToken, 'PUT', `/v1/admin/acme-ca-credentials/${ca}`, write)
    if (!isCredential(body)) throw new ApiError('Invalid API response', 0, 'invalid_response')
    return body
  },
  async fetchZeroSSLFromEmail(accessToken: string, write: ZeroSSLEABEmailRequest): Promise<AcmeCACredential> {
    const body = await call(accessToken, 'POST', '/v1/admin/acme-ca-credentials/zerossl/eab-from-email', write)
    if (!isCredential(body) || body.ca !== 'zerossl') throw new ApiError('Invalid API response', 0, 'invalid_response')
    return body
  },
}
