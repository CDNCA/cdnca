import { ApiError, networkApiError, responseApiError } from './auth'

export interface LoginCaptchaChallenge {
  id: string
  image: string
  expires_at: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/** Issues a built-in sign-in CAPTCHA (shown after login_captcha_required). */
export async function issueLoginCaptcha(signal?: AbortSignal): Promise<LoginCaptchaChallenge> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/auth/login-captchas`, { method: 'POST', credentials: 'omit', cache: 'no-store', signal })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const value: unknown = await response.json().catch(() => null)
  const body = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
  if (response.status !== 201 || !body || Object.keys(body).length !== 3 ||
    typeof body.id !== 'string' || !uuidPattern.test(body.id) ||
    typeof body.image !== 'string' || !body.image.startsWith('data:image/png;base64,') || body.image.length > 65536 ||
    typeof body.expires_at !== 'string' || !Number.isFinite(Date.parse(body.expires_at))) {
    throw new ApiError('Invalid login CAPTCHA response', 502, 'invalid_response')
  }
  return body as unknown as LoginCaptchaChallenge
}

/** Whether the error asks the sign-in form to show (or refresh) the CAPTCHA. */
export function loginCaptchaNeeded(error: unknown): boolean {
  return error instanceof ApiError && (error.code === 'login_captcha_required' || error.code === 'login_captcha_invalid')
}
