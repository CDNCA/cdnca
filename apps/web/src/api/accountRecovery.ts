import { ApiError, networkApiError, responseApiError } from './auth'

export interface AccountRecoveryRequest {
  username: string
}

export interface AccountRecoveryConfirmation {
  token: string
  recovery_context: string
  new_password: string
  confirm_password: string
}

export interface AccountRecoveryRequestResult {
  data: {
    code: 'account_recovery_request_accepted'
    accepted_at: string
  }
}

export class AccountRecoveryApiError extends ApiError {
  readonly retryAfterSeconds: number | null

  constructor(error: ApiError, retryAfterSeconds: number | null = null) {
    super(error.message, error.status, error.code, error.requestId)
    this.name = 'AccountRecoveryApiError'
    this.retryAfterSeconds = retryAfterSeconds
  }
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function retryAfterSeconds(response: Response): number {
  const value = response.headers.get('Retry-After')
  if (value && /^\d+$/.test(value)) {
    const seconds = Number(value)
    if (Number.isSafeInteger(seconds) && seconds >= 1 && seconds <= 86_400) return seconds
  }
  return 900
}

function isRFC3339DateTime(value: string): boolean {
  const match = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day <= days[month - 1] && !Number.isNaN(Date.parse(value))
}

function isRequestResult(value: unknown): value is AccountRecoveryRequestResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const envelope = value as Record<string, unknown>
  if (Object.keys(envelope).length !== 1 || !envelope.data || typeof envelope.data !== 'object') {
    return false
  }
  const data = envelope.data as Record<string, unknown>
  return Object.keys(data).length === 2 &&
    data.code === 'account_recovery_request_accepted' &&
    typeof data.accepted_at === 'string' &&
    isRFC3339DateTime(data.accepted_at)
}

async function post(
  path: string,
  body: object,
  idempotencyKey: string,
  expectedStatus: 202 | 204,
): Promise<AccountRecoveryRequestResult | undefined> {
  let response: Response

  try {
    response = await fetch(`${apiRoot}${path}`, {
      method: 'POST',
      credentials: 'omit',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': idempotencyKey,
      },
      body: JSON.stringify(body),
    })
  } catch {
    throw networkApiError()
  }

  if (!response.ok) {
    const error = await responseApiError(response)
    throw new AccountRecoveryApiError(
      error,
      response.status === 429 ? retryAfterSeconds(response) : null,
    )
  }

  if (response.status !== expectedStatus) throw invalidResponse()
  if (expectedStatus === 204) return undefined

  const contentType = response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase()
  if (contentType !== 'application/json') throw invalidResponse()
  const result = await response.json().catch(() => null)
  if (!isRequestResult(result)) throw invalidResponse()
  return result
}

export const accountRecoveryApi = {
  request(input: AccountRecoveryRequest, idempotencyKey: string) {
    return post(
      '/v1/account-recovery/requests',
      input,
      idempotencyKey,
      202,
    )
  },
  confirm(input: AccountRecoveryConfirmation, idempotencyKey: string) {
    return post('/v1/account-recovery/confirmations', input, idempotencyKey, 204)
  },
}
