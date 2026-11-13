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

export interface TenantMemberPasswordReset {
  user_id: string
  temporary_password: string
  /** Always true: the member must change it at the next sign-in. */
  password_change_required: boolean
  /** The retained result of an earlier request with the same key. */
  replayed: boolean
  result_expires_at: string
}

/** What keeps a member from being deleted (409 tenant_member_owns_resources). */
export interface TenantMemberOwnedResources {
  package_subscriptions: number
  l4_forwards: number
  package_sites: number
  /** Resources that move to transfer_to. */
  transferable: number
}

export interface CreateTenantMemberInput {
  username: string
  display_name: string
  email: string
  password: string
}

export interface TenantMemberInvitation {
  id: string
  email: string
  status: 'pending' | 'accepted' | 'revoked' | 'expired'
  created_at: string
  expires_at: string
}

export interface AcceptTenantMemberInvitationInput {
  token: string
  username: string
  display_name: string
  password: string
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
    const error = await responseApiError(response.clone())
    if (error.code === 'tenant_member_owns_resources') {
      const resources = ((await response.json().catch(() => null)) as { error?: { resources?: unknown } } | null)?.error?.resources
      if (isOwnedResources(resources)) Object.assign(error, { resources })
    }
    throw error
  }
  if (response.status === 204) return undefined as T
  const body: unknown = await response.json().catch(() => null)
  if (!body || typeof body !== 'object') throw new ApiError('Invalid members response', 502, 'invalid_response')
  return body as T
}

function isOwnedResources(value: unknown): value is TenantMemberOwnedResources {
  if (!value || typeof value !== 'object') return false
  const counts = value as Record<string, unknown>
  return ['package_subscriptions', 'l4_forwards', 'package_sites', 'transferable']
    .every(key => Number.isSafeInteger(counts[key]) && (counts[key] as number) >= 0)
}

/** The counts of a tenant_member_owns_resources refusal, when the response carried them. */
export function ownedResourcesOf(error: unknown): TenantMemberOwnedResources | undefined {
  return error instanceof ApiError ? (error as ApiError & { resources?: TenantMemberOwnedResources }).resources : undefined
}

const transferQuery = (transferTo?: string) => transferTo ? `?transfer_to=${encodeURIComponent(transferTo)}` : ''

export const tenantMembersApi = {
  list: async (accessToken: string) => (await call<{ items: TenantMember[] }>(accessToken, '/v1/tenant/members')).items,
  create: (accessToken: string, input: CreateTenantMemberInput) =>
    call<TenantMember>(accessToken, '/v1/tenant/members', { method: 'POST', body: JSON.stringify(input) }),
  suspend: (accessToken: string, userID: string, transferTo?: string) =>
    call<TenantMember>(accessToken, `/v1/tenant/members/${encodeURIComponent(userID)}/suspend${transferQuery(transferTo)}`, { method: 'POST' }),
  resume: (accessToken: string, userID: string) =>
    call<TenantMember>(accessToken, `/v1/tenant/members/${encodeURIComponent(userID)}/resume`, { method: 'POST' }),
  /** Deletes a sub-account; with transferTo its transferable resources go to that member first. */
  remove: (accessToken: string, userID: string, transferTo?: string) =>
    call<void>(accessToken, `/v1/tenant/members/${encodeURIComponent(userID)}${transferQuery(transferTo)}`, { method: 'DELETE' }),
  /** Requires (or withdraws) a password change at the member's next sign-in. */
  setPasswordChange: (accessToken: string, userID: string, required: boolean) =>
    call<TenantMember>(accessToken, `/v1/tenant/members/${encodeURIComponent(userID)}/password-change`, { method: 'PUT', body: JSON.stringify({ required }) }),
  /**
   * Resets a sub-account's password. If the outcome is unknown (network error,
   * 5xx), call again with the same idempotencyKey within 10 minutes: the
   * server returns the same password once (replayed) instead of resetting again.
   */
  resetPassword: (accessToken: string, userID: string, idempotencyKey: string) =>
    call<TenantMemberPasswordReset>(accessToken, `/v1/tenant/members/${encodeURIComponent(userID)}/password-reset`,
      { method: 'POST', headers: { 'Idempotency-Key': idempotencyKey } }),
  listInvitations: async (accessToken: string) =>
    (await call<{ items: TenantMemberInvitation[] }>(accessToken, '/v1/tenant/member-invitations')).items,
  invite: (accessToken: string, email: string) =>
    call<TenantMemberInvitation>(accessToken, '/v1/tenant/member-invitations', { method: 'POST', body: JSON.stringify({ email }) }),
  revokeInvitation: (accessToken: string, invitationID: string) =>
    call<void>(accessToken, `/v1/tenant/member-invitations/${encodeURIComponent(invitationID)}/revoke`, { method: 'POST' }),
  // Anonymous: the invitation token is the credential.
  acceptInvitation: (input: AcceptTenantMemberInvitationInput) =>
    call<TenantMember>(null, '/v1/auth/member-invitations/accept', { method: 'POST', body: JSON.stringify(input) }),
}
