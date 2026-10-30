import { ApiError, networkApiError } from './auth'

export type MfaAuthenticationMethod = 'totp' | 'recovery_code'

export type MfaStatus =
  | { status: 'inactive' }
  | {
      status: 'enrollment_pending'
      credential_id: string
      method: 'totp'
      enrollment_expires_at: string
    }
  | { status: 'active'; credential_id: string; method: 'totp' }

export interface MfaWriteMetadata {
  requestId: string
  idempotencyKey: string
  traceparent: string
}

export interface BeginMfaEnrollmentInput {
  account_label: string
}

export type MfaEnrollmentResult =
  | {
      credential_id: string
      secret: string
      provisioning_uri: string
      expires_at: string
      replayed: false
    }
  | { credential_id: string; expires_at: string; replayed: true }

export interface ActivateMfaEnrollmentInput {
  code: string
}

export type MfaActivationResult =
  | {
      credential_id: string
      recovery_codes: string[]
      activated_at: string
      replayed: false
    }
  | { credential_id: string; activated_at: string; replayed: true }

export interface MfaTerminalInput {
  authentication: { method: MfaAuthenticationMethod; code: string }
  reason: string
}

export interface CreateStepUpProofInput {
  tenant_id: string
  audience: string
  action: string
  authentication: { method: MfaAuthenticationMethod; code: string }
  ttl_seconds: number
  max_uses: number
}

export type MfaStepUpProofResult =
  | {
      proof_id: string
      token: string
      method: MfaAuthenticationMethod
      issued_at: string
      expires_at: string
      max_uses: number
      replayed: false
    }
  | {
      proof_id: string
      method: MfaAuthenticationMethod
      issued_at: string
      expires_at: string
      max_uses: number
      replayed: true
    }

export type StepUpProofResult = MfaStepUpProofResult

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const metadataPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const idempotencyPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const traceparentPattern = /^00-([0-9a-f]{32})-([0-9a-f]{16})-(?:00|01)$/
const errorCodePattern = /^mfa_[a-z0-9_]+$/
const totpSecretPattern = /^[A-Z2-7]{32}$/
const recoveryCodePattern = /^[A-Z2-7]{8}(?:-[A-Z2-7]{8}){3}$/
const stepUpTokenPattern = /^[A-Za-z0-9_-]{43}$/

function invalidResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function invalidRequest(): ApiError {
  return new ApiError('MFA request was invalid', 400, 'invalid_request')
}

function cryptoUnavailable(): ApiError {
  return new ApiError('Web Crypto is unavailable', 400, 'crypto_unavailable')
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === keys.length && actual.every((key) => keys.includes(key))
}

function rfc3339(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = /^(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return day <= days[month - 1] && !Number.isNaN(Date.parse(value))
}

function canonicalUUID(value: unknown): value is string {
  return typeof value === 'string' && uuidPattern.test(value)
}

function provisioningText(value: string): boolean {
  if (!value || value.trim() !== value) return false
  return ![...value].some((character) => {
    const codePoint = character.codePointAt(0)!
    return codePoint <= 0x1f || codePoint >= 0x7f && codePoint <= 0x9f ||
      codePoint === 0x2028 || codePoint === 0x2029
  })
}

function accountLabel(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 && provisioningText(value) &&
    value.trim() === value && !/[:/\\]/.test(value)
}

function provisioningURI(value: unknown, secret: string, expectedAccountLabel: string): value is string {
  if (typeof value !== 'string') return false
  try {
    const uri = new URL(value)
    const keys = [...uri.searchParams.keys()]
    const expectedKeys = ['algorithm', 'digits', 'issuer', 'period', 'secret']
    const issuer = uri.searchParams.get('issuer')
    const encodedLabel = uri.pathname.slice(1)
    const label = decodeURIComponent(encodedLabel)
    return uri.protocol === 'otpauth:' && uri.host === 'totp' && !uri.username && !uri.password &&
      !uri.hash && keys.length === expectedKeys.length && new Set(keys).size === keys.length &&
      keys.every((key) => expectedKeys.includes(key)) && issuer !== null && provisioningText(issuer) &&
      !/[:/\\]/.test(issuer) && uri.pathname.startsWith('/') && !encodedLabel.includes('/') &&
      !/%2f/i.test(encodedLabel) && label === `${issuer}:${expectedAccountLabel}` &&
      uri.searchParams.get('algorithm') === 'SHA1' && uri.searchParams.get('digits') === '6' &&
      uri.searchParams.get('period') === '30' && uri.searchParams.get('secret') === secret
  } catch {
    return false
  }
}

function canonicalTraceparent(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = traceparentPattern.exec(value)
  return Boolean(match && match[1] !== '0'.repeat(32) && match[2] !== '0'.repeat(16))
}

function parseStatus(value: unknown): MfaStatus {
  if (!record(value) || typeof value.status !== 'string') throw invalidResponse()
  if (value.status === 'inactive' && exactKeys(value, ['status'])) return { status: 'inactive' }
  if (value.status === 'enrollment_pending' && exactKeys(value, [
    'status', 'credential_id', 'method', 'enrollment_expires_at',
  ]) && canonicalUUID(value.credential_id) && value.method === 'totp' && rfc3339(value.enrollment_expires_at)) {
    return {
      status: value.status,
      credential_id: value.credential_id,
      method: value.method,
      enrollment_expires_at: value.enrollment_expires_at,
    }
  }
  if (value.status === 'active' && exactKeys(value, ['status', 'credential_id', 'method']) &&
    canonicalUUID(value.credential_id) && value.method === 'totp') {
    return { status: value.status, credential_id: value.credential_id, method: value.method }
  }
  throw invalidResponse()
}

function parseEnrollment(value: unknown, status: number, expectedAccountLabel: string): MfaEnrollmentResult {
  if (!record(value) || !canonicalUUID(value.credential_id) || !rfc3339(value.expires_at)) {
    throw invalidResponse()
  }
  if (status === 201 && exactKeys(value, [
    'credential_id', 'secret', 'provisioning_uri', 'expires_at', 'replayed',
  ]) && typeof value.secret === 'string' && totpSecretPattern.test(value.secret) &&
    provisioningURI(value.provisioning_uri, value.secret, expectedAccountLabel) && value.replayed === false) {
    return {
      credential_id: value.credential_id,
      secret: value.secret,
      provisioning_uri: value.provisioning_uri,
      expires_at: value.expires_at,
      replayed: false,
    }
  }
  if (status === 200 && exactKeys(value, ['credential_id', 'expires_at', 'replayed']) &&
    value.replayed === true) {
    return { credential_id: value.credential_id, expires_at: value.expires_at, replayed: true }
  }
  throw invalidResponse()
}

function parseActivation(value: unknown, status: number): MfaActivationResult {
  if (!record(value) || !canonicalUUID(value.credential_id) || !rfc3339(value.activated_at)) {
    throw invalidResponse()
  }
  if (status === 201 && exactKeys(value, [
    'credential_id', 'recovery_codes', 'activated_at', 'replayed',
  ]) && Array.isArray(value.recovery_codes) && value.recovery_codes.length === 10 &&
    value.recovery_codes.every((code) => typeof code === 'string' && recoveryCodePattern.test(code)) &&
    new Set(value.recovery_codes).size === value.recovery_codes.length && value.replayed === false) {
    return {
      credential_id: value.credential_id,
      recovery_codes: [...value.recovery_codes],
      activated_at: value.activated_at,
      replayed: false,
    }
  }
  if (status === 200 && exactKeys(value, ['credential_id', 'activated_at', 'replayed']) &&
    value.replayed === true) {
    return { credential_id: value.credential_id, activated_at: value.activated_at, replayed: true }
  }
  throw invalidResponse()
}

export function parseStepUpProof(value: unknown, status: number): MfaStepUpProofResult {
  const maxUses = record(value) ? value.max_uses : undefined
  if (!record(value) || !canonicalUUID(value.proof_id) ||
    (value.method !== 'totp' && value.method !== 'recovery_code') ||
    !rfc3339(value.issued_at) || !rfc3339(value.expires_at) ||
    typeof maxUses !== 'number' || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 5) {
    throw invalidResponse()
  }
  if (status === 201 && exactKeys(value, [
    'proof_id', 'token', 'method', 'issued_at', 'expires_at', 'max_uses', 'replayed',
  ]) && typeof value.token === 'string' && stepUpTokenPattern.test(value.token) && value.replayed === false) {
    return {
      proof_id: value.proof_id,
      token: value.token,
      method: value.method,
      issued_at: value.issued_at,
      expires_at: value.expires_at,
      max_uses: maxUses,
      replayed: false,
    }
  }
  if (status === 200 && exactKeys(value, [
    'proof_id', 'method', 'issued_at', 'expires_at', 'max_uses', 'replayed',
  ]) && value.replayed === true) {
    return {
      proof_id: value.proof_id,
      method: value.method,
      issued_at: value.issued_at,
      expires_at: value.expires_at,
      max_uses: maxUses,
      replayed: true,
    }
  }
  throw invalidResponse()
}

async function jsonBody(response: Response): Promise<unknown> {
  if (response.headers.get('Content-Type') !== 'application/json') throw invalidResponse()
  try {
    return await response.json()
  } catch {
    throw invalidResponse()
  }
}

async function apiError(response: Response): Promise<ApiError> {
  let value: unknown
  try {
    value = await jsonBody(response)
  } catch {
    if (response.status === 401 || response.status === 403) {
      return new ApiError('API response was invalid', response.status, 'invalid_response')
    }
    throw invalidResponse()
  }
  if (!record(value) || !exactKeys(value, ['error']) || !record(value.error) ||
    !exactKeys(value.error, ['code', 'message', 'request_id']) ||
    typeof value.error.code !== 'string' || !errorCodePattern.test(value.error.code) ||
    typeof value.error.message !== 'string' || typeof value.error.request_id !== 'string' ||
    !metadataPattern.test(value.error.request_id)) {
    if (response.status === 401 || response.status === 403) {
      return new ApiError('API response was invalid', response.status, 'invalid_response')
    }
    throw invalidResponse()
  }
  return new ApiError('API request failed', response.status, value.error.code, value.error.request_id)
}

function randomHex(bytes: number): string {
  if (!globalThis.crypto?.getRandomValues) throw cryptoUnavailable()
  const values = new Uint8Array(bytes)
  globalThis.crypto.getRandomValues(values)
  if (values.every((value) => value === 0)) values[values.length - 1] = 1
  return [...values].map((value) => value.toString(16).padStart(2, '0')).join('')
}

function suffix(): string {
  if (!globalThis.crypto?.getRandomValues) throw cryptoUnavailable()
  return globalThis.crypto.randomUUID?.() ?? randomHex(16)
}

function traceparent(): string {
  return `00-${randomHex(16)}-${randomHex(8)}-01`
}

export function createMfaWriteMetadata(
  action: 'enroll' | 'activate' | 'step-up' | 'step_up' | 'disable' | 'reset',
): MfaWriteMetadata {
  return {
    requestId: `mfa-${action}-${suffix()}`,
    idempotencyKey: `mfa-${action}-${suffix()}`,
    traceparent: traceparent(),
  }
}

function writeHeaders(accessToken: string, metadata: MfaWriteMetadata): HeadersInit {
  if (!accessToken || !record(metadata) || !exactKeys(metadata, ['requestId', 'idempotencyKey', 'traceparent']) ||
    !metadataPattern.test(metadata.requestId) || !idempotencyPattern.test(metadata.idempotencyKey) ||
    !canonicalTraceparent(metadata.traceparent)) throw invalidRequest()
  return {
    Authorization: `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestId,
    Traceparent: metadata.traceparent,
  }
}

async function send(path: string, init: RequestInit): Promise<Response> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, { ...init, credentials: 'include' })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await apiError(response)
  return response
}

async function getStatus(accessToken: string): Promise<MfaStatus> {
  if (!accessToken) throw invalidRequest()
  const response = await send('/v1/account/mfa', {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'X-Request-ID': `mfa-status-${suffix()}`,
      Traceparent: traceparent(),
    },
  })
  if (response.status !== 200) throw invalidResponse()
  return parseStatus(await jsonBody(response))
}

async function beginEnrollment(
  accessToken: string,
  input: BeginMfaEnrollmentInput,
  metadata: MfaWriteMetadata,
): Promise<MfaEnrollmentResult> {
  if (!record(input) || !exactKeys(input, ['account_label']) || !accountLabel(input.account_label)) {
    throw invalidRequest()
  }
  const response = await send('/v1/account/mfa/enrollments', {
    method: 'POST', headers: writeHeaders(accessToken, metadata), body: JSON.stringify(input),
  })
  if (response.status !== 200 && response.status !== 201) throw invalidResponse()
  return parseEnrollment(await jsonBody(response), response.status, input.account_label)
}

async function activateEnrollment(
  accessToken: string,
  credentialID: string,
  input: ActivateMfaEnrollmentInput,
  metadata: MfaWriteMetadata,
): Promise<MfaActivationResult> {
  if (!canonicalUUID(credentialID) || !record(input) || !exactKeys(input, ['code']) ||
    typeof input.code !== 'string' || !/^\d{6}$/.test(input.code)) throw invalidRequest()
  const response = await send(`/v1/account/mfa/enrollments/${credentialID}/activate`, {
    method: 'POST', headers: writeHeaders(accessToken, metadata), body: JSON.stringify(input),
  })
  if (response.status !== 200 && response.status !== 201) throw invalidResponse()
  return parseActivation(await jsonBody(response), response.status)
}

function stepUpText(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128 &&
    value.trim() === value && ![...value].some((character) => {
      const codePoint = character.codePointAt(0)!
      return codePoint <= 0x1f || codePoint >= 0x7f && codePoint <= 0x9f ||
        codePoint === 0x2028 || codePoint === 0x2029
    })
}

function validStepUpInput(value: unknown): value is CreateStepUpProofInput {
  if (!record(value) || !exactKeys(value, [
    'tenant_id', 'audience', 'action', 'authentication', 'ttl_seconds', 'max_uses',
  ]) || !canonicalUUID(value.tenant_id) || !stepUpText(value.audience) || !stepUpText(value.action) ||
    !record(value.authentication) || !exactKeys(value.authentication, ['method', 'code']) ||
    (value.authentication.method !== 'totp' && value.authentication.method !== 'recovery_code') ||
    typeof value.authentication.code !== 'string' || value.authentication.code.length < 6 ||
    value.authentication.code.length > 64) return false
  const ttlSeconds = value.ttl_seconds
  const maxUses = value.max_uses
  if (typeof ttlSeconds !== 'number' || !Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 300 ||
    typeof maxUses !== 'number' || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 5) return false
  return value.authentication.method === 'totp'
    ? /^\d{6}$/.test(value.authentication.code)
    : recoveryCodePattern.test(value.authentication.code)
}

async function createStepUpProof(
  accessToken: string,
  input: CreateStepUpProofInput,
  metadata: MfaWriteMetadata,
): Promise<MfaStepUpProofResult> {
  if (!validStepUpInput(input)) throw invalidRequest()
  const response = await send('/v1/account/mfa/step-up-proofs', {
    method: 'POST', headers: writeHeaders(accessToken, metadata), body: JSON.stringify(input),
  })
  if (response.status !== 200 && response.status !== 201) throw invalidResponse()
  return parseStepUpProof(await jsonBody(response), response.status)
}

async function terminal(
  action: 'disable' | 'reset',
  accessToken: string,
  input: MfaTerminalInput,
  metadata: MfaWriteMetadata,
): Promise<void> {
  if (!record(input) || !exactKeys(input, ['authentication', 'reason']) ||
    !record(input.authentication) || !exactKeys(input.authentication, ['method', 'code']) ||
    typeof input.reason !== 'string' || input.reason.trim() !== input.reason ||
    input.reason.length === 0 || input.reason.length > 512 ||
    input.authentication.method !== 'totp' && input.authentication.method !== 'recovery_code' ||
    typeof input.authentication.code !== 'string' ||
    (input.authentication.method === 'totp'
      ? !/^\d{6}$/.test(input.authentication.code)
      : !recoveryCodePattern.test(input.authentication.code))) throw invalidRequest()
  const response = await send(`/v1/account/mfa/${action}`, {
    method: 'POST', headers: writeHeaders(accessToken, metadata), body: JSON.stringify(input),
  })
  if (response.status !== 204 || response.headers.has('Content-Type') || await response.text() !== '') {
    throw invalidResponse()
  }
}

export const mfaApi = {
  getStatus,
  beginEnrollment,
  activateEnrollment,
  createStepUpProof,
  disable(accessToken: string, input: MfaTerminalInput, metadata: MfaWriteMetadata) {
    return terminal('disable', accessToken, input, metadata)
  },
  reset(accessToken: string, input: MfaTerminalInput, metadata: MfaWriteMetadata) {
    return terminal('reset', accessToken, input, metadata)
  },
}
