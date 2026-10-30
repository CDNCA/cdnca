import { ApiError, networkApiError, responseApiError } from './auth'

export interface PasswordLoginChallengeInput {
  username: string
  password: string
  scope_id: string
  human_token?: string
  captcha?: { id: string; answer: string }
}

export interface PasswordLoginChallengeReceipt {
  accepted: true
  challenge_id: string
  expires_at: string
  replayed: boolean
}

export interface PasswordLoginMetadata {
  idempotencyKey: string
  requestId: string
}

export class PasswordLoginChallengeError extends ApiError {
  readonly retryAfterSeconds: number | null

  constructor(error: ApiError, retryAfterSeconds: number | null) {
    super(error.message, error.status, error.code, error.requestId, error.params)
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export function passwordLoginMetadata(): PasswordLoginMetadata {
  if (!globalThis.crypto?.getRandomValues) throw new ApiError('Web Crypto unavailable', 400, 'crypto_unavailable')
  const random = () => {
    const bytes = new Uint8Array(16)
    globalThis.crypto.getRandomValues(bytes)
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
  }
  return { idempotencyKey: `password-login-${random()}`, requestId: random() }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export async function sendPasswordLoginChallenge(
  input: PasswordLoginChallengeInput,
  metadata: PasswordLoginMetadata,
  signal?: AbortSignal,
): Promise<PasswordLoginChallengeReceipt> {
  if (!input.username || !input.password || !uuidPattern.test(input.scope_id) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(metadata.idempotencyKey) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(metadata.requestId)) {
    throw new ApiError('Invalid login challenge request', 400, 'invalid_request')
  }
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/auth/login-challenges`, {
      method: 'POST', credentials: 'omit', cache: 'no-store',
      signal,
      headers: {
        'Content-Type': 'application/json', 'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
      },
      body: JSON.stringify({
        username: input.username, password: input.password, scope_id: input.scope_id,
        ...(input.human_token ? { human_token: input.human_token } : {}),
        ...(input.captcha ? { captcha: input.captcha } : {}),
      }),
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) {
    const rawRetry = response.headers.get('Retry-After') ?? ''
    const retry = /^\d+$/.test(rawRetry) ? Number(rawRetry) : NaN
    throw new PasswordLoginChallengeError(await responseApiError(response), response.status === 429
      ? Number.isSafeInteger(retry) && retry > 0 && retry <= 86_400 ? retry : 60
      : null)
  }
  const body: unknown = await response.json().catch(() => null)
  const envelope = body && typeof body === 'object' && !Array.isArray(body) ? body as Record<string, unknown> : null
  const value = envelope?.data
  const receipt = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
  if (response.status !== 202 || response.headers.get('Content-Type')?.split(';')[0] !== 'application/json' ||
    !envelope || Object.keys(envelope).length !== 1 || !receipt || Object.keys(receipt).length !== 4 ||
    receipt.accepted !== true || typeof receipt.challenge_id !== 'string' || !uuidPattern.test(receipt.challenge_id) ||
    typeof receipt.expires_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(receipt.expires_at) ||
    !Number.isFinite(Date.parse(receipt.expires_at)) || typeof receipt.replayed !== 'boolean') {
    throw new ApiError('Invalid login challenge response', 502, 'invalid_response')
  }
  return receipt as unknown as PasswordLoginChallengeReceipt
}

export interface LoginCaptchaConfig {
  provider: 'tencent' | 'geetest_v4'
  appId: string
}

/**
 * Reads the public login methods and returns the external CAPTCHA widget for the
 * challenge channel, or null when that channel uses the built-in protection.
 */
export async function loginCaptchaConfig(channel: 'email' | 'sms', signal?: AbortSignal): Promise<LoginCaptchaConfig | null> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}/v1/auth/login-methods`, { method: 'GET', credentials: 'omit', cache: 'no-store', signal })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  const body: unknown = await response.json().catch(() => null)
  const data = body && typeof body === 'object' && !Array.isArray(body) ? (body as { data?: unknown }).data : null
  const value = data && typeof data === 'object' && !Array.isArray(data) ? data as Record<string, unknown> : null
  if (!value) throw new ApiError('Invalid login methods response', 502, 'invalid_response')
  const mode = value[channel === 'email' ? 'email_anti_abuse_mode' : 'sms_anti_abuse_mode']
  const provider = value.captcha_provider
  const appId = value.captcha_app_id
  if ((mode !== 'tencent' && mode !== 'geetest_v4') || provider !== mode ||
    typeof appId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(appId)) {
    return null
  }
  return { provider: mode, appId }
}
