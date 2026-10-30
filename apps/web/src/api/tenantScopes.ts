import { networkApiError, responseApiError } from './auth'

/** One tenant scope (identity.TenantScope): the small projection platform administrators pick a tenant target from. */
export interface TenantScope {
  scope_id: string
  tenant_id: string
  tenant_name: string
  status: string
  display_id: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

/** GET /v1/admin/tenant-scopes (platform session; identity.users.manage or platform.admin). */
export async function listTenantScopes(accessToken: string, params: { search?: string; limit?: number } = {}): Promise<TenantScope[]> {
  const query = new URLSearchParams({ page: '1', limit: String(params.limit ?? 100) })
  if (params.search) query.set('search', params.search)
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/admin/tenant-scopes?${query}`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = await response.json() as { items?: TenantScope[] }
  return Array.isArray(body.items) ? body.items : []
}
