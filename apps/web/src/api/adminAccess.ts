import { ApiError, networkApiError, responseApiError } from './auth'

// Platform administration access allowlist (GET/PUT /v1/admin/admin-access-policy).
export interface AdminAccessPolicy {
  revision: number
  enabled: boolean
  allowlist: string[]
  updated_at: string | null
  /** The address the control plane sees for this browser. */
  current_ip: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function isPolicy(value: unknown): value is AdminAccessPolicy {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return Number.isSafeInteger(record.revision) && Number(record.revision) >= 0 && typeof record.enabled === 'boolean' &&
    Array.isArray(record.allowlist) && record.allowlist.length <= 64 &&
    record.allowlist.every(entry => typeof entry === 'string' && /^[0-9a-f:.]+(?:\/\d{1,3})?$/i.test(entry)) &&
    (record.updated_at === null || typeof record.updated_at === 'string') && typeof record.current_ip === 'string'
}

async function call(accessToken: string, init: RequestInit = {}): Promise<AdminAccessPolicy> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/admin-access-policy`, {
      ...init, credentials: 'include', cache: 'no-store',
      headers: { Authorization: `Bearer ${accessToken}`, ...(init.body ? { 'Content-Type': 'application/json' } : {}) },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body: unknown = await response.json().catch(() => null)
  if (!isPolicy(body)) throw new ApiError('Invalid admin access policy response', 502, 'invalid_response')
  return body
}

export const adminAccessApi = {
  get: (accessToken: string) => call(accessToken),
  update: (accessToken: string, input: { expected_revision: number; enabled: boolean; allowlist: string[] }) =>
    call(accessToken, { method: 'PUT', body: JSON.stringify(input) }),
}

/** Splits the textarea into entries (spaces, commas or new lines). */
export function parseAllowlist(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map(entry => entry.trim()).filter(Boolean))]
}
