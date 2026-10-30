import { ApiError, networkApiError, responseApiError } from './auth'

// Tenant members / sub-accounts (/v1/tenant/members).
export interface TenantMember {
  user_id: string
  username: string
  display_name: string
  email: string | null
  status: 'active' | 'suspended' | 'disabled'
  role: string
  owner: boolean
  created_at: string
  /** Must change the password at the next sign-in. */
  password_change_required: boolean
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function call<T>(accessToken: string | null, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init, credentials: 'include', cache: 'no-store',
      headers: {
        ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...(init.headers as Record<string, string> | undefined),
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) {
    throw await responseApiError(response)
  }
  if (response.status === 204) return undefined as T
  const body: unknown = await response.json().catch(() => null)
  if (!body || typeof body !== 'object') throw new ApiError('Invalid members response', 502, 'invalid_response')
  return body as T
}

export const tenantMembersApi = {
  list: async (accessToken: string) => (await call<{ items: TenantMember[] }>(accessToken, '/v1/tenant/members')).items,
}
