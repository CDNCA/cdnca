import { ApiError, networkApiError, responseApiError } from './auth'

// ADR 0014 LIC-BAN-04 (control-api installationlock.Lock): GET /v1/installation-lock
// is the banner's source; POST …/check asks the controller to fetch the state now.
export type InstallationLockReason = 'installation_banned' | 'lease_revoked' | 'lease_expired' | 'service_ticket_expired'
export interface InstallationLock {
  locked: boolean
  reason?: InstallationLockReason | string
  ban_id?: string
  reason_code?: string
  reason_text?: string
  until?: string | null
  // fix-ipswitch: the license was rebound to another server's master IP; this
  // controller gets no new lease (frozen, sites keep serving).
  rebound?: boolean
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function parse(value: unknown): InstallationLock {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof (value as InstallationLock).locked !== 'boolean') {
    throw new ApiError('Invalid installation lock', 502, 'response_invalid')
  }
  const v = value as Record<string, unknown>
  const text = (key: string, max: number) => (typeof v[key] === 'string' && (v[key] as string).length <= max ? v[key] as string : undefined)
  const until = text('until', 64)
  return { locked: v.locked as boolean, reason: text('reason', 64), ban_id: text('ban_id', 64), reason_code: text('reason_code', 64),
    reason_text: text('reason_text', 2000), until: until && !Number.isNaN(Date.parse(until)) ? until : null,
    rebound: v.rebound === true }
}

async function call(token: string, method: 'GET' | 'POST'): Promise<InstallationLock> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/installation-lock${method === 'POST' ? '/check' : ''}`,
      { method, credentials: 'include', headers: { Authorization: `Bearer ${token}` } })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return parse(await response.json().catch(() => null))
}

export const installationLockApi = {
  current: (token: string) => call(token, 'GET'),
  check: (token: string) => call(token, 'POST'),
}
