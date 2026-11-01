import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

// RuntimeFeature names an optional control-plane runtime (GET /v1/runtime-features).
// A flag is true exactly when that runtime's routes are mounted, so menu items
// with requiredRuntime are hidden instead of opening a page that answers 404.
export const runtimeFeatureNames = ['cache_control', 'custom_rbac', 'plugin_webhooks', 'approval_center', 'market', 'package_auto_renew', 'origin_auth'] as const
// demo_locked: the signed-in account is a locked demo account (CONTROL_DEMO_LOCKED_ACCOUNTS);
// optional in the response, so it is not in runtimeFeatureNames.
export type RuntimeFeature = typeof runtimeFeatureNames[number] | 'demo_locked'

export async function fetchRuntimeFeatures(token: string): Promise<RuntimeFeature[]> {
  if (!token) throw new ApiError('Not signed in', 401, 'unauthenticated')
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/runtime-features`, {
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}` },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body = (await response.json().catch(() => undefined)) as { features?: Record<string, unknown> } | undefined
  const features = body?.features
  if (!features || typeof features !== 'object' ||
    runtimeFeatureNames.some((name) => typeof features[name] !== 'boolean')) {
    throw new ApiError('Invalid response', 502, 'response_invalid')
  }
  const enabled: RuntimeFeature[] = runtimeFeatureNames.filter((name) => features[name] === true)
  if (features.demo_locked === true) enabled.push('demo_locked')
  return enabled
}
