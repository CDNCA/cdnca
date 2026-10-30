import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const moduleCodePattern = /^(module|pack|theme)\.[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/

// GrantedModules is GET /v1/modules: the module, pack and theme feature codes
// the verified local lease grants (empty unless the lease is valid). Menu
// items with requiredModule are shown only for listed codes (PA-15).
export interface GrantedModules {
  status: string
  lease_serial: number
  modules: string[]
}

export async function fetchGrantedModules(token: string): Promise<GrantedModules> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/modules`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = (await response.json().catch(() => undefined)) as Partial<GrantedModules> | undefined
  if (!body || typeof body.status !== 'string' || typeof body.lease_serial !== 'number' ||
    !Array.isArray(body.modules) || body.modules.some((code) => typeof code !== 'string' || !moduleCodePattern.test(code))) {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
  return { status: body.status, lease_serial: body.lease_serial, modules: [...body.modules] }
}
