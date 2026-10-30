import { ApiError, networkApiError, responseApiError } from './auth'

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digestPattern = /^[0-9a-f]{64}$/
const allowedMethods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
const documentKeys = ['enabled', 'max_body_bytes', 'max_event_bytes', 'max_value_bytes', 'methods', 'request_body_field_allowlist', 'request_header_allowlist', 'response_body_field_allowlist', 'response_header_allowlist', 'uri_prefixes']

export interface SiteCapturePolicyDocument {
  enabled: boolean
  methods: string[]
  uri_prefixes: string[]
  request_header_allowlist: string[]
  response_header_allowlist: string[]
  request_body_field_allowlist: string[]
  response_body_field_allowlist: string[]
  max_value_bytes: number
  max_body_bytes: number
  max_event_bytes: number
}

export interface SiteCapturePolicy {
  scope_id: string
  site_id: string
  revision: number
  document: SiteCapturePolicyDocument
  evidence_digest: string
  updated_at: string
  updated_by: string
  request_id: string
}

/** A readable site that never saved a policy: default document, create with expected_revision 0. */
export interface SiteCapturePolicyUnconfigured {
  scope_id: string
  site_id: string
  state: 'unconfigured'
  revision: 0
  document: SiteCapturePolicyDocument
}

export interface SiteCapturePolicyUpdate {
  expected_revision: number
  document: SiteCapturePolicyDocument
}

export interface SiteCapturePolicyWriteResult {
  policy: SiteCapturePolicy
  replayed: boolean
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function stringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 128 && value.every((item) => typeof item === 'string')
}

function integer(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value)
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected)
}

function canonicalList(values: string[]): boolean {
  return values.every((value, index) => value.length > 0 && value.length <= 1024 && (index === 0 || values[index - 1] < value))
}

function parseDocument(value: unknown): SiteCapturePolicyDocument {
  if (!record(value) || !exactKeys(value, documentKeys) || typeof value.enabled !== 'boolean' || !stringList(value.methods) || !stringList(value.uri_prefixes) ||
    !stringList(value.request_header_allowlist) || !stringList(value.response_header_allowlist) ||
    !stringList(value.request_body_field_allowlist) || !stringList(value.response_body_field_allowlist) ||
    !integer(value.max_value_bytes) || value.max_value_bytes < 1 || value.max_value_bytes > 16384 ||
    !integer(value.max_body_bytes) || value.max_body_bytes < 1 || value.max_body_bytes > 1048576 ||
    !integer(value.max_event_bytes) || value.max_event_bytes < 256 || value.max_event_bytes > 1048576 ||
    !canonicalList(value.methods) || !value.methods.every((method) => allowedMethods.has(method)) ||
    !canonicalList(value.uri_prefixes) || !value.uri_prefixes.every((prefix) => prefix.startsWith('/') && !/[?#\r\n\0]/u.test(prefix)) ||
    !canonicalList(value.request_header_allowlist) || !canonicalList(value.response_header_allowlist) ||
    !canonicalList(value.request_body_field_allowlist) || !canonicalList(value.response_body_field_allowlist)) {
    throw new ApiError('Invalid site capture response', 502, 'invalid_response')
  }
  const captures = value.request_header_allowlist.length + value.response_header_allowlist.length +
    value.request_body_field_allowlist.length + value.response_body_field_allowlist.length
  if (value.enabled ? captures === 0 : captures !== 0 || value.methods.length !== 0 || value.uri_prefixes.length !== 0) {
    throw new ApiError('Invalid site capture response', 502, 'invalid_response')
  }
  return value as unknown as SiteCapturePolicyDocument
}

function parsePolicy(value: unknown, scopeID: string, siteID: string): SiteCapturePolicy {
  if (!record(value) || value.scope_id !== scopeID || value.site_id !== siteID || !integer(value.revision) || value.revision < 1 ||
    typeof value.evidence_digest !== 'string' || !digestPattern.test(value.evidence_digest) ||
    typeof value.updated_at !== 'string' || Number.isNaN(Date.parse(value.updated_at)) ||
    typeof value.updated_by !== 'string' || !uuidPattern.test(value.updated_by) || typeof value.request_id !== 'string') {
    throw new ApiError('Invalid site capture response', 502, 'invalid_response')
  }
  return { ...value, document: parseDocument(value.document) } as SiteCapturePolicy
}

function parseRead(value: unknown, scopeID: string, siteID: string): SiteCapturePolicy | SiteCapturePolicyUnconfigured {
  if (record(value) && value.state === 'unconfigured') {
    if (!exactKeys(value, ['document', 'revision', 'scope_id', 'site_id', 'state']) || value.scope_id !== scopeID ||
      value.site_id !== siteID || value.revision !== 0) {
      throw new ApiError('Invalid site capture response', 502, 'invalid_response')
    }
    const document = parseDocument(value.document)
    if (document.enabled) throw new ApiError('Invalid site capture response', 502, 'invalid_response')
    return { scope_id: scopeID, site_id: siteID, state: 'unconfigured', revision: 0, document }
  }
  return parsePolicy(value, scopeID, siteID)
}

function validateTarget(scopeID: string, siteID: string): void {
  if (!uuidPattern.test(scopeID) || !uuidPattern.test(siteID)) {
    throw new ApiError('Invalid site capture target', 400, 'site_capture_invalid_request')
  }
}

async function request(path: string, accessToken: string, init: RequestInit): Promise<Response> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Accept: 'application/json', Authorization: `Bearer ${accessToken}`, ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  return response
}

async function responseJSON(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    throw new ApiError('Invalid site capture response', 502, 'invalid_response')
  }
}

function path(scopeID: string, siteID: string): string {
  return `/v1/tenant-scopes/${scopeID}/sites/${siteID}/telemetry-capture-policy`
}

export const siteCapturePolicyApi = {
  async get(accessToken: string, scopeID: string, siteID: string, signal?: AbortSignal): Promise<SiteCapturePolicy | SiteCapturePolicyUnconfigured> {
    validateTarget(scopeID, siteID)
    const response = await request(path(scopeID, siteID), accessToken, { method: 'GET', signal })
    return parseRead(await responseJSON(response), scopeID, siteID)
  },

  async update(
    accessToken: string,
    scopeID: string,
    siteID: string,
    input: SiteCapturePolicyUpdate,
    metadata: { idempotencyKey: string; requestID: string; traceID: string },
    signal?: AbortSignal,
  ): Promise<SiteCapturePolicyWriteResult> {
    validateTarget(scopeID, siteID)
    const body = JSON.stringify(input)
    const response = await request(path(scopeID, siteID), accessToken, {
      method: 'PUT', signal, body,
      headers: {
        'Content-Type': 'application/json', 'Idempotency-Key': metadata.idempotencyKey,
        'X-Request-ID': metadata.requestID, 'X-Trace-ID': metadata.traceID,
      },
    })
    const value = await responseJSON(response)
    if (!record(value) || typeof value.replayed !== 'boolean') {
      throw new ApiError('Invalid site capture response', 502, 'invalid_response')
    }
    return { replayed: value.replayed, policy: parsePolicy(value.policy, scopeID, siteID) }
  },
}
