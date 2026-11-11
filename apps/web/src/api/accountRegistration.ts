import { ApiError, networkApiError, responseApiError } from './auth'

export type AccountRegistrationVerificationChannel = 'email' | 'sms'

export interface AccountRegistrationRequest {
  username: string
  password: string
  display_name: string
  email: string
  phone: string
  terms_accepted: boolean
  terms_version: string
  verification_channel: AccountRegistrationVerificationChannel
}

export interface AccountRegistrationChallengeRequest {
  username: string
  email: string
  phone: string
  verification_channel: AccountRegistrationVerificationChannel
  human_token: string
}

export interface AccountRegistrationChallengeVerificationRequest {
  challenge_id: string
  username: string
  email: string
  phone: string
  verification_channel: AccountRegistrationVerificationChannel
  otp: string
}

export interface AccountRegistrationRequestMetadata {
  idempotencyKey: string
  requestId: string
}

export interface AccountRegistrationResult {
  accepted: true
  replayed: boolean
}

export interface AccountRegistrationChallengeResult {
  accepted: true
  challenge_id: string
  expires_at: string
  replayed: boolean
}

export class AccountRegistrationApiError extends ApiError {
  readonly retryAfterSeconds: number | null

  constructor(error: ApiError, retryAfterSeconds: number | null = null) {
    super(error.message, error.status, error.code, error.requestId)
    this.name = 'AccountRegistrationApiError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const rfc3339Pattern = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/
const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function serialize(input: AccountRegistrationRequest): string {
  return JSON.stringify({
    username: input.username,
    password: input.password,
    display_name: input.display_name,
    email: input.email,
    phone: input.phone,
    terms_accepted: input.terms_accepted,
    terms_version: input.terms_version,
    verification_channel: input.verification_channel,
  })
}

function serializeChallenge(input: AccountRegistrationChallengeRequest): string {
  return JSON.stringify({
    username: input.username,
    email: input.email,
    phone: input.phone,
    verification_channel: input.verification_channel,
    human_token: input.human_token,
  })
}

function serializeVerification(input: AccountRegistrationChallengeVerificationRequest): string {
  return JSON.stringify({
    challenge_id: input.challenge_id,
    username: input.username,
    email: input.email,
    phone: input.phone,
    verification_channel: input.verification_channel,
    otp: input.otp,
  })
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid account registration response', 502, 'invalid_response')
}

function isRFC3339DateTime(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = rfc3339Pattern.exec(value)
  if (!match || Number.isNaN(Date.parse(value))) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day <= days[month - 1]
}

function parseRegistrationResult(value: unknown): AccountRegistrationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidResponse()
  const result = value as Record<string, unknown>
  if (
    Object.keys(result).sort().join(',') !== 'accepted,replayed' ||
    result.accepted !== true ||
    typeof result.replayed !== 'boolean'
  ) {
    throw invalidResponse()
  }
  return { accepted: true, replayed: result.replayed }
}

function parseChallengeResult(value: unknown): AccountRegistrationChallengeResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalidResponse()
  const envelope = value as Record<string, unknown>
  if (Object.keys(envelope).join(',') !== 'data' || !envelope.data || typeof envelope.data !== 'object') {
    throw invalidResponse()
  }
  const data = envelope.data as Record<string, unknown>
  if (
    Object.keys(data).sort().join(',') !== 'accepted,challenge_id,expires_at,replayed' ||
    data.accepted !== true ||
    typeof data.challenge_id !== 'string' ||
    !uuidPattern.test(data.challenge_id) ||
    !isRFC3339DateTime(data.expires_at) ||
    typeof data.replayed !== 'boolean'
  ) {
    throw invalidResponse()
  }
  return {
    accepted: true,
    challenge_id: data.challenge_id,
    expires_at: data.expires_at,
    replayed: data.replayed,
  }
}

function retryAfterSeconds(response: Response): number | null {
  if (response.status !== 429) return null
  const value = response.headers.get('Retry-After')
  if (value && /^\d+$/.test(value)) {
    const seconds = Number(value)
    if (Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 3600) return seconds
  }
  return 60
}

async function post(
  path: string,
  metadata: AccountRegistrationRequestMetadata,
  serializedBody: string,
  canonicalBody: string,
): Promise<Response> {
  if (
    !metadataPattern.test(metadata.idempotencyKey) ||
    !metadataPattern.test(metadata.requestId) ||
    serializedBody !== canonicalBody
  ) {
    throw new ApiError('Invalid account registration request', 400, 'account_registration_invalid_input')
  }

  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestId,
      },
      body: serializedBody,
    })
  } catch {
    throw networkApiError()
  }

  if (!response.ok) {
    const error = await responseApiError(response)
    throw new AccountRegistrationApiError(error, retryAfterSeconds(response))
  }
  return response
}

async function createChallenge(
  input: AccountRegistrationChallengeRequest,
  metadata: AccountRegistrationRequestMetadata,
  serializedBody = serializeChallenge(input),
): Promise<AccountRegistrationChallengeResult> {
  const response = await post(
    '/v1/auth/registration-challenges',
    metadata,
    serializedBody,
    serializeChallenge(input),
  )
  if (response.status !== 202 || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  return parseChallengeResult(await response.json().catch(() => null))
}

async function verifyChallenge(
  input: AccountRegistrationChallengeVerificationRequest,
  metadata: AccountRegistrationRequestMetadata,
  serializedBody = serializeVerification(input),
): Promise<void> {
  const response = await post(
    '/v1/auth/registration-challenge-verifications',
    metadata,
    serializedBody,
    serializeVerification(input),
  )
  if (response.status !== 204) throw invalidResponse()
}

async function register(
  input: AccountRegistrationRequest,
  metadata: AccountRegistrationRequestMetadata,
  serializedBody = serialize(input),
): Promise<AccountRegistrationResult> {
  const response = await post('/v1/auth/register', metadata, serializedBody, serialize(input))
  if (response.status !== 202 || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  return parseRegistrationResult(await response.json().catch(() => null))
}

export interface AccountRegistrationCaptcha {
  id: string
  answer: string
}

export type AccountRegistrationMode = 'builtin' | 'verified' | 'closed'

function serializeBuiltIn(input: AccountRegistrationRequest, captcha: AccountRegistrationCaptcha): string {
  return JSON.stringify({ ...JSON.parse(serialize(input)) as Record<string, unknown>, captcha: { id: captcha.id, answer: captcha.answer } })
}

/**
 * builtin registration: a control plane without the Turnstile registration service
 * (fresh install) registers with the built-in image CAPTCHA. The server says
 * which flow applies through GET /v1/auth/login-methods registration_mode.
 */
async function registrationMode(signal?: AbortSignal): Promise<AccountRegistrationMode> {
  try {
    const response = await fetch(`${apiRoot}/v1/auth/login-methods`, { method: 'GET', credentials: 'omit', cache: 'no-store', signal })
    if (!response.ok) return 'verified'
    const body: unknown = await response.json().catch(() => null)
    const data = body && typeof body === 'object' ? (body as { data?: unknown }).data : null
    if (!data || typeof data !== 'object') return 'verified'
    const value = data as Record<string, unknown>
    if (value.registration_enabled !== true) return 'closed'
    return value.registration_mode === 'builtin' ? 'builtin' : 'verified'
  } catch {
    return 'verified'
  }
}

async function registerBuiltIn(
  input: AccountRegistrationRequest,
  captcha: AccountRegistrationCaptcha,
  metadata: AccountRegistrationRequestMetadata,
): Promise<AccountRegistrationResult> {
  const body = serializeBuiltIn(input, captcha)
  const response = await post('/v1/auth/register', metadata, body, body)
  if (response.status !== 202 || response.headers.get('Content-Type')?.split(';', 1)[0] !== 'application/json') {
    throw invalidResponse()
  }
  return parseRegistrationResult(await response.json().catch(() => null))
}

/** GET /v1/auth/registration-config (null: unreadable). */
export interface AccountRegistrationConfig {
  mode: AccountRegistrationMode
  ready: boolean
  email: { required: boolean, available: boolean }
  sms: { required: boolean, available: boolean }
}

async function registrationConfig(signal?: AbortSignal): Promise<AccountRegistrationConfig | null> {
  try {
    const response = await fetch(`${apiRoot}/v1/auth/registration-config`, { method: 'GET', credentials: 'omit', cache: 'no-store', signal })
    if (!response.ok) return null
    const body = await response.json().catch(() => null) as { data?: AccountRegistrationConfig } | null
    return body?.data && typeof body.data === 'object' ? body.data : null
  } catch {
    return null
  }
}

/** The channels the console page may offer: the required and sendable ones,
 * else (nothing required) every sendable one. */
export function registrationChannels(config: AccountRegistrationConfig | null): AccountRegistrationVerificationChannel[] {
  if (!config) return ['email', 'sms']
  const all: AccountRegistrationVerificationChannel[] = ['email', 'sms']
  const required = all.filter((channel) => config[channel].required)
  return (required.length ? required : all).filter((channel) => config[channel].available)
}

export const accountRegistrationApi = {
  registrationConfig,
  registrationMode,
  registerBuiltIn,
  createChallenge,
  verifyChallenge,
  register,
  serialize,
  serializeChallenge,
  serializeVerification,
}
