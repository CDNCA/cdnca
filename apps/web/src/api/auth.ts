export type ScopeKind = 'platform' | 'tenant'

export interface ImpersonationMarker {
  grant_id: string
  actor_user_id: string
  actor_display_name: string
  subject_user_id: string
  subject_display_name: string
  tenant_id: string
  expires_at: string
}

export interface Principal {
  user_id: string
  /** 数字账号 ID（用户概览「账号 ID」）。 */
  display_id?: string
  scope_id: string
  scope_kind: ScopeKind
  tenant_id: string | null
  username: string
  display_name: string
  roles: string[]
  permissions: string[]
  /** An administrator requires a new password before anything else (403 password_change_required). */
  password_change_required?: boolean
  impersonation?: ImpersonationMarker
}

export interface AuthResponse {
  access_token: string
  token_type: 'Bearer'
  expires_in: number
  principal: Principal
  impersonation?: ImpersonationMarker
}

export interface LoginRequest {
  username: string
  password: string
  scope_id?: string
  login_challenge?: { challenge_id: string; otp: string }
  /** Solved built-in sign-in CAPTCHA, required after login_captcha_required. */
  captcha?: { id: string; answer: string }
}

export interface LoginVerificationRequirement {
  channel: 'email' | 'sms'
  scope_id: string
}

interface ErrorEnvelope {
  error?: {
    code?: string
    message?: string
    request_id?: string
    reason_code?: string
    outcome?: string
    params?: unknown
    challenge?: unknown
    capability?: unknown
    rule_packs?: unknown
    details?: unknown
  }
}

/** The nodes of a release refused because their agent lacks a gated
 * capability (node_capability_unavailable). */
export interface CapabilityRefusal {
  node_id: string
  capability: string
  required_version: number
  other_node_ids: string[]
}

const capabilityNamePattern = /^CAPABILITY_NAME_[A-Z0-9_]{1,64}$/

function capabilityRefusal(raw: unknown): CapabilityRefusal | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const value = raw as Record<string, unknown>
  const others = value.other_node_ids
  if (typeof value.node_id !== 'string' || !challengeUUIDPattern.test(value.node_id) ||
    typeof value.capability !== 'string' || !capabilityNamePattern.test(value.capability) ||
    typeof value.required_version !== 'number' || !Number.isSafeInteger(value.required_version) || value.required_version < 1 ||
    !Array.isArray(others) || others.length > 10000 ||
    !others.every((id) => typeof id === 'string' && challengeUUIDPattern.test(id))) return undefined
  return { node_id: value.node_id, capability: value.capability, required_version: value.required_version,
    other_node_ids: others as string[] }
}

/** The nodes of a release refused because their node artifact set lacks a
 * rule pack the release's sites use (rule_pack_unavailable). The release is
 * kept and published automatically once the packs reach the nodes. */
export interface RulePackRefusal {
  node_id: string
  sha256: string[]
  other_node_ids: string[]
  /** A refused security activation was recorded and starts by itself once the nodes have the packs. */
  auto_resume?: boolean
}

const rulePackDigestPattern = /^[0-9a-f]{64}$/

function rulePackRefusal(raw: unknown): RulePackRefusal | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const value = raw as Record<string, unknown>
  const digests = value.sha256
  const others = value.other_node_ids
  if (typeof value.node_id !== 'string' || !challengeUUIDPattern.test(value.node_id) ||
    !Array.isArray(digests) || digests.length < 1 || digests.length > 64 ||
    !digests.every((digest) => typeof digest === 'string' && rulePackDigestPattern.test(digest)) ||
    !Array.isArray(others) || others.length > 10000 ||
    !others.every((id) => typeof id === 'string' && challengeUUIDPattern.test(id))) return undefined
  const refusal: RulePackRefusal = { node_id: value.node_id, sha256: digests as string[], other_node_ids: others as string[] }
  if (value.auto_resume === true) refusal.auto_resume = true
  return refusal
}

/** The node and site of a release refused because the node has not installed
 * the site's JS challenge policy (challenge_policy_unavailable). */
export interface ChallengePolicyRefusal {
  node_id: string
  site_id: string
  domain: string
  policy_version: number
  other_node_ids: string[]
}

const challengeUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const challengeDomainPattern = /^[a-z0-9*][a-z0-9.*-]{0,252}$/

function challengePolicyRefusal(raw: unknown): ChallengePolicyRefusal | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const value = raw as Record<string, unknown>
  const others = value.other_node_ids
  if (typeof value.node_id !== 'string' || !challengeUUIDPattern.test(value.node_id) ||
    typeof value.site_id !== 'string' || !challengeUUIDPattern.test(value.site_id) ||
    typeof value.domain !== 'string' || !challengeDomainPattern.test(value.domain) ||
    typeof value.policy_version !== 'number' || !Number.isSafeInteger(value.policy_version) || value.policy_version < 1 ||
    !Array.isArray(others) || others.length > 10000 ||
    !others.every((id) => typeof id === 'string' && challengeUUIDPattern.test(id))) return undefined
  return { node_id: value.node_id, site_id: value.site_id, domain: value.domain, policy_version: value.policy_version,
    other_node_ids: others as string[] }
}

/** Fired when a session request is refused because its region changed. */
export const sessionRegionChangedEvent = 'cdnca:session-region-changed'
export const passwordChangeRequiredEvent = 'cdnca:password-change-required'
/** Fired when the control plane is under a migration hold (only the frozen console answers). */
export const migrationHoldEvent = 'cdnca:control-migration-hold'

/** Re-binds the session to its current region with the password. */
export async function verifySessionRegion(accessToken: string, password: string): Promise<void> {
  let response: Response
  try {
    response = await fetch(`${(import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')}/v1/auth/session-region-verifications`, {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
  } catch {
    throw networkApiError()
  }
  if (response.status !== 204) throw await responseApiError(response)
}

const stableErrorCodePattern = /^[a-z][a-z0-9_]{0,63}$/
const safeRequestIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const loginUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export interface ApiErrorSignal {
  status: number
  code: string
}

type ApiErrorObserver = (signal: ApiErrorSignal) => void

let apiErrorObserver: ApiErrorObserver | undefined

export function setApiErrorObserver(observer: ApiErrorObserver): () => void {
  apiErrorObserver = observer
  return () => {
    if (apiErrorObserver === observer) apiErrorObserver = undefined
  }
}

function notifyApiError(status: number, code: string): void {
  const signal = {
    status:Number.isInteger(status) && status >= 0 && status <= 599 ? status : 0,
    code:stableErrorCodePattern.test(code) ? code : 'request_failed',
  }
  try { apiErrorObserver?.(signal) } catch { /* Reporting cannot replace the request error. */ }
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId?: string
  declare readonly params?: LoginVerificationRequirement
  declare challenge?: ChallengePolicyRefusal
  declare capability?: CapabilityRefusal
  declare rulePacks?: RulePackRefusal
  /** The refused request field of a validation_error (error.details.field), e.g. cname_domain. */
  declare field?: string
  /** With field: why it was refused (error.details.reason, e.g. invalid / required). */
  declare reason?: string
  /** Same as reason (the stream form reads this name). */
  declare fieldReason?: string
  /** reason_code of an upgrade_target_blocked refusal (e.g. same_version). */
  declare reasonCode?: string
  /** Retry-After of a 429 response, in seconds (1..86400). */
  declare retryAfter?: number
  /** D3: the sites still running a policy whose delete was refused (security_policy_in_use error.details.sites). */
  declare inUseSites?: { id: string; domain: string }[]
  /** LIC-REC-03: whether an entitlement refresh error installed the lease (error.outcome). */
  declare outcome?: 'not_applied' | 'unknown' | 'applied'
  /** ADD-10: the target a cache operation create refused (invalid_request error.details). */
  declare targetRejection?: { ordinal: number; reason: string }

  constructor(message: string, status = 0, code = 'network_error', requestId?: string, params?: LoginVerificationRequirement) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
    if (params) this.params = params
    notifyApiError(status, code)
  }
}

export function networkApiError(): ApiError {
  return new ApiError('Network request failed', 0, 'network_error')
}

export async function responseApiError(response: Response): Promise<ApiError> {
  const body = (await response.json().catch(() => ({}))) as ErrorEnvelope
  const code = body?.error?.code && stableErrorCodePattern.test(body.error.code)
    ? body.error.code
    : 'request_failed'
  const requestId = body?.error?.request_id && safeRequestIdPattern.test(body.error.request_id)
    ? body.error.request_id
    : undefined
  const raw = body?.error?.params
  let params: LoginVerificationRequirement | undefined
  if (response.status === 401 && code === 'login_verification_required' && raw &&
    typeof raw === 'object' && !Array.isArray(raw)) {
    const values = raw as Record<string, unknown>
    if (Object.keys(values).length === 2 && (values.channel === 'email' || values.channel === 'sms') &&
      typeof values.scope_id === 'string' && loginUUIDPattern.test(values.scope_id)) {
      params = { channel: values.channel, scope_id: values.scope_id }
    }
  }
  const error = new ApiError('API request failed', response.status, code, requestId, params)
  if (code === 'session_region_changed' && typeof window !== 'undefined') {
    window.dispatchEvent(new Event(sessionRegionChangedEvent))
  }
  if (code === 'password_change_required' && typeof window !== 'undefined') {
    window.dispatchEvent(new Event(passwordChangeRequiredEvent))
  }
  if (code === 'control_migration_hold' && typeof window !== 'undefined') {
    window.dispatchEvent(new Event(migrationHoldEvent))
  }
  const outcome = body?.error?.outcome
  if (code.startsWith('entitlement_refresh_') && (outcome === 'not_applied' || outcome === 'unknown' || outcome === 'applied')) {
    error.outcome = outcome
  }
  const retryAfter = response.status === 429 ? Number(response.headers?.get?.('Retry-After') ?? NaN) : NaN
  if (Number.isSafeInteger(retryAfter) && retryAfter > 0 && retryAfter <= 86_400) error.retryAfter = retryAfter
  if (code === 'challenge_policy_unavailable') {
    const challenge = challengePolicyRefusal(body?.error?.challenge)
    if (challenge) error.challenge = challenge
  }
  if (code === 'node_capability_unavailable') {
    const capability = capabilityRefusal(body?.error?.capability)
    if (capability) error.capability = capability
  }
  if (code === 'supply_in_use') {
    // ADR 0012 ML-18b: error.details carries online_available / normal_subscriptions (api/marketSupplier supplyInUse).
    (error as ApiError & { refusal?: unknown }).refusal = body
  }
  if (code === 'rule_pack_unavailable') {
    const rulePacks = rulePackRefusal(body?.error?.rule_packs)
    if (rulePacks) error.rulePacks = rulePacks
  }
  if (code === 'security_policy_in_use') {
    const sites = (body?.error?.details as { sites?: unknown } | undefined)?.sites
    if (Array.isArray(sites)) {
      error.inUseSites = sites.slice(0, 5).flatMap((site: unknown) => {
        const { id, domain } = (site ?? {}) as { id?: unknown; domain?: unknown }
        return typeof id === 'string' && loginUUIDPattern.test(id) && typeof domain === 'string' && domain.length > 0 && domain.length <= 253
          ? [{ id, domain }] : []
      })
    }
  }
  if (code === 'upgrade_target_blocked') {
    const reason = body?.error?.reason_code
    if (typeof reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(reason)) error.reasonCode = reason
  }
  if (code === 'invalid_request') {
    const details = body?.error?.details as { field?: unknown; target_ordinal?: unknown; reason?: unknown } | undefined
    if (details && details.field === 'targets' && Number.isSafeInteger(details.target_ordinal) && Number(details.target_ordinal) >= 1 &&
      typeof details.reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(details.reason)) {
      error.targetRejection = { ordinal: Number(details.target_ordinal), reason: details.reason }
    }
  }
  attachFieldRefusal(error, body?.error?.details)
  return error
}

/**
 * Sets error.field / reason / fieldReason from a validation refusal's
 * details {field, reason} (the request JSON path, nested a.b[0].c,
 * fix-fielderr-be). Only validation_error, *_validation_error and
 * *_invalid_request count. For the API clients that build their own ApiError
 * (fix-fielderr-be5) as well as responseApiError.
 */
export function attachFieldRefusal(error: ApiError, details: unknown): ApiError {
  const code = error.code
  if (code !== 'validation_error' && !/^[a-z][a-z0-9_]*_(?:validation_error|invalid_request)$/.test(code)) return error
  const value = details as { field?: unknown; reason?: unknown } | null | undefined
  if (value && typeof value.field === 'string' && value.field.length <= 256 &&
    /^[a-z][a-z0-9_]{0,63}(?:\.[a-z0-9_]{1,64}|\[\d{1,4}\])*$/.test(value.field)) {
    error.field = value.field
    if (typeof value.reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value.reason)) { error.reason = value.reason; error.fieldReason = value.reason }
  }
  return error
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response

  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }

  if (!response.ok) {
    throw await responseApiError(response)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

export const authApi = {
  login(input: LoginRequest, idempotencyKey?: string, signal?: AbortSignal) {
    if (input.login_challenge && (!input.scope_id || !loginUUIDPattern.test(input.scope_id) ||
      !loginUUIDPattern.test(input.login_challenge.challenge_id) || !/^\d{6}$/.test(input.login_challenge.otp) ||
      !idempotencyKey || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(idempotencyKey)) ||
      input.captcha && (!loginUUIDPattern.test(input.captcha.id) || !/^[A-Za-z0-9]{1,8}$/.test(input.captcha.answer))) {
      throw new ApiError('Invalid login request', 400, 'invalid_request')
    }
    return request<AuthResponse>('/v1/auth/login', {
      method: 'POST',
      signal,
      ...(input.login_challenge ? { headers: { 'Idempotency-Key': idempotencyKey! } } : {}),
      body: JSON.stringify(input),
    })
  },
  refresh() {
    return request<AuthResponse>('/v1/auth/refresh', { method: 'POST' })
  },
  logout() {
    return request<void>('/v1/auth/logout', { method: 'POST' })
  },
  me(accessToken: string, signal?: AbortSignal) {
    return request<Principal>('/v1/auth/me', {
      signal,
      headers: { Authorization: `Bearer ${accessToken}` },
    })
  },
}
