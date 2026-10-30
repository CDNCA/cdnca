// vis-1: whether the sign-in page may offer a sign-up link. The server decides
// (GET /v1/auth/login-methods registration_enabled: the registration switch is
// on and the registration endpoints are mounted); any failure hides the link.
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export async function registrationAvailable(signal?: AbortSignal): Promise<boolean> {
  try {
    const response = await fetch(`${apiRoot}/v1/auth/login-methods`, { method: 'GET', credentials: 'omit', cache: 'no-store', signal })
    if (!response.ok) return false
    const body: unknown = await response.json().catch(() => null)
    const data = body && typeof body === 'object' ? (body as { data?: unknown }).data : null
    return Boolean(data && typeof data === 'object' && (data as Record<string, unknown>).registration_enabled === true)
  } catch {
    return false
  }
}
