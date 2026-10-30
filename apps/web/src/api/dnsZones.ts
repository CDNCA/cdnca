import { ApiError, networkApiError, type ScopeKind } from './auth'

export type DNSZoneStatus = 'draft' | 'failed'
export type DNSRecordType = 'A' | 'AAAA' | 'CNAME' | 'TXT'

export interface DNSZone {
  id: string
  scope_id: string
  provider_id: string
  name: string
  status: DNSZoneStatus
  version: number
  created_at: string
  updated_at: string
}

export interface DNSRecord {
  id: string
  scope_id: string
  zone_id: string
  name: string
  type: DNSRecordType
  content: string
  ttl: number
  status: DNSZoneStatus
  version: number
  created_at: string
  updated_at: string
}

export interface DNSZoneList { items: DNSZone[] }
export interface DNSRecordList { items: DNSRecord[] }

export interface DNSZoneBinding {
  scopeKind: ScopeKind
  scopeID: string
  providers: Array<{ id: string; scope_id: string }>
}

export interface CreateDNSZoneInput {
  target_scope_id: string
  provider_id: string
  name: string
}

export interface CreateDNSRecordInput {
  target_scope_id: string
  zone_id: string
  name: string
  type: DNSRecordType
  content: string
  ttl: number
}

export interface UpdateDNSRecordInput {
  expected_version: number
  name: string
  type: DNSRecordType
  content: string
  ttl: number
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const requestIDPattern = /^[A-Za-z0-9._-]{1,128}$/
const errorCodePattern = /^[a-z][a-z0-9_]{0,63}$/

function responseInvalid(): ApiError {
  return new ApiError('DNS response is invalid', 0, 'response_invalid')
}

function requestInvalid(): ApiError {
  return new ApiError('DNS request is invalid', 400, 'invalid_request')
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  return actual.length === expected.length && actual.every((key, index) => key === expected[index])
}

function isDateTime(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(value)
  if (!match) return false
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const offsetHour = Number(match[7] ?? 0)
  const offsetMinute = Number(match[8] ?? 0)
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1
}

function validLabels(value: string, record: boolean): boolean {
  if (value.length < 1 || value.length > 253 || [...value].some((char) => char.codePointAt(0)! > 0x7f)) return false
  const pattern = record
    ? /^(?:\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$/
    : /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
  return value.split('.').every((label) => pattern.test(label))
}

export function canonicalDNSZoneName(raw: string): string | null {
  const value = raw.trim().replace(/\.$/, '').toLowerCase()
  return validLabels(value, false) ? value : null
}

export function canonicalDNSRecordName(raw: string): string | null {
  const value = raw.trim().replace(/\.$/, '').toLowerCase()
  return value === '@' || validLabels(value, true) ? value : null
}

function canonicalIPv4(raw: string): string | null {
  const parts = raw.trim().split('.')
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9]\d{0,2})$/.test(part) || Number(part) > 255)) {
    return null
  }
  return parts.join('.')
}

function canonicalIPv6(raw: string): string | null {
  const value = raw.trim()
  if (!value.includes(':') || value.includes('%')) return null
  try {
    const hostname = new URL(`http://[${value}]/`).hostname
    if (!hostname.startsWith('[') || !hostname.endsWith(']')) return null
    const canonical = hostname.slice(1, -1)
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical)
    if (!mapped) return canonical
    const high = Number.parseInt(mapped[1], 16)
    const low = Number.parseInt(mapped[2], 16)
    return `::ffff:${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`
  } catch {
    return null
  }
}

function validUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) return false
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) return false
  }
  return true
}

export function canonicalDNSRecordContent(type: DNSRecordType, raw: string): string | null {
  const value = raw.trim()
  if (type === 'A') return canonicalIPv4(value)
  if (type === 'AAAA') return canonicalIPv6(value)
  if (type === 'CNAME') return canonicalDNSZoneName(value)
  if (type !== 'TXT' || !validUnicode(value) || value.length < 1 ||
    new TextEncoder().encode(value).length > 1024 || /[\0\r\n]/.test(value)) return null
  return value
}

function canonicalRecordInput<T extends { name: string; type: DNSRecordType; content: string; ttl: number }>(input: T): T {
  const name = canonicalDNSRecordName(input.name)
  const content = canonicalDNSRecordContent(input.type, input.content)
  if (!name || content === null || !Number.isInteger(input.ttl) || input.ttl < 60 || input.ttl > 86400) {
    throw requestInvalid()
  }
  return { ...input, name, content }
}

function isZone(value: unknown): value is DNSZone {
  if (!isObject(value) || !exactKeys(value, [
    'id', 'scope_id', 'provider_id', 'name', 'status', 'version', 'created_at', 'updated_at',
  ])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.provider_id === 'string' && uuidPattern.test(value.provider_id) &&
    typeof value.name === 'string' && canonicalDNSZoneName(value.name) === value.name &&
    (value.status === 'draft' || value.status === 'failed') && positiveInteger(value.version) &&
    isDateTime(value.created_at) && isDateTime(value.updated_at)
}

function isRecordValue(value: unknown): value is DNSRecord {
  if (!isObject(value) || !exactKeys(value, [
    'id', 'scope_id', 'zone_id', 'name', 'type', 'content', 'ttl', 'status',
    'version', 'created_at', 'updated_at',
  ])) return false
  return typeof value.id === 'string' && uuidPattern.test(value.id) &&
    typeof value.scope_id === 'string' && uuidPattern.test(value.scope_id) &&
    typeof value.zone_id === 'string' && uuidPattern.test(value.zone_id) &&
    typeof value.name === 'string' && canonicalDNSRecordName(value.name) === value.name &&
    (value.type === 'A' || value.type === 'AAAA' || value.type === 'CNAME' || value.type === 'TXT') &&
    typeof value.content === 'string' && canonicalDNSRecordContent(value.type, value.content) === value.content &&
    Number.isInteger(value.ttl) && Number(value.ttl) >= 60 && Number(value.ttl) <= 86400 &&
    (value.status === 'draft' || value.status === 'failed') && positiveInteger(value.version) &&
    isDateTime(value.created_at) && isDateTime(value.updated_at)
}

function generatedRequestID(action: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `dns-${action}-${suffix}`
}

async function jsonBody(response: Response): Promise<unknown> {
  if (response.headers.get('Content-Type') !== 'application/json') throw responseInvalid()
  try {
    const source = await response.text()
    const value = JSON.parse(source) as unknown
    if (hasDuplicateJSONKeys(source)) throw responseInvalid()
    return value
  } catch {
    throw responseInvalid()
  }
}

function hasDuplicateJSONKeys(source: string): boolean {
  let index = 0
  const whitespace = () => {
    while (/\s/.test(source[index] ?? '')) index += 1
  }
  const string = (): string => {
    const start = index
    index += 1
    while (index < source.length) {
      if (source[index] === '\\') index += 2
      else if (source[index++] === '"') break
    }
    return JSON.parse(source.slice(start, index)) as string
  }
  const value = (): boolean => {
    whitespace()
    if (source[index] === '{') {
      index += 1
      const keys = new Set<string>()
      whitespace()
      while (source[index] !== '}') {
        const key = string()
        if (keys.has(key)) return true
        keys.add(key)
        whitespace()
        index += 1
        if (value()) return true
        whitespace()
        if (source[index] !== ',') break
        index += 1
        whitespace()
      }
      index += 1
      return false
    }
    if (source[index] === '[') {
      index += 1
      whitespace()
      while (source[index] !== ']') {
        if (value()) return true
        whitespace()
        if (source[index] !== ',') break
        index += 1
        whitespace()
      }
      index += 1
      return false
    }
    if (source[index] === '"') {
      string()
      return false
    }
    while (index < source.length && !/[\s,\]}]/.test(source[index])) index += 1
    return false
  }
  return value()
}

async function apiError(response: Response, requestID: string): Promise<ApiError> {
  const value = await jsonBody(response)
  if (!isObject(value) || !exactKeys(value, ['error']) || !isObject(value.error) ||
    !exactKeys(value.error, ['code', 'message', 'request_id']) ||
    typeof value.error.code !== 'string' || !errorCodePattern.test(value.error.code) ||
    typeof value.error.message !== 'string' || value.error.message.length < 1 || value.error.message.length > 1024 ||
    value.error.request_id !== requestID) throw responseInvalid()
  return new ApiError('API request failed', response.status, value.error.code, requestID)
}

async function request(
  accessToken: string,
  path: string,
  requestID: string,
  expectedStatus: number,
  init: RequestInit = {},
): Promise<Response> {
  if (!accessToken || !requestIDPattern.test(requestID)) throw requestInvalid()
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'X-Request-ID': requestID,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (response.headers.get('X-Request-ID') !== requestID) throw responseInvalid()
  if (!response.ok) throw await apiError(response, requestID)
  if (response.status !== expectedStatus) throw responseInvalid()
  return response
}

async function jsonRequest(
  accessToken: string, path: string, requestID: string, expectedStatus: number, init: RequestInit = {},
): Promise<unknown> {
  return jsonBody(await request(accessToken, path, requestID, expectedStatus, init))
}

async function emptyRequest(
  accessToken: string, path: string, requestID: string, init: RequestInit,
): Promise<void> {
  const response = await request(accessToken, path, requestID, 204, init)
  if (response.headers.has('Content-Type') || await response.text() !== '') throw responseInvalid()
}

function providerScope(binding: DNSZoneBinding, providerID: string): string {
  if (!uuidPattern.test(binding.scopeID)) throw responseInvalid()
  const providers = new Map<string, string>()
  for (const provider of binding.providers) {
    if (!uuidPattern.test(provider.id) || !uuidPattern.test(provider.scope_id) || providers.has(provider.id)) {
      throw responseInvalid()
    }
    if (binding.scopeKind === 'tenant' && provider.scope_id !== binding.scopeID) throw responseInvalid()
    providers.set(provider.id, provider.scope_id)
  }
  const scopeID = providers.get(providerID)
  if (!scopeID) throw responseInvalid()
  return scopeID
}

function validateZone(value: unknown, binding: DNSZoneBinding): DNSZone {
  if (!isZone(value)) throw responseInvalid()
  const expectedScopeID = providerScope(binding, value.provider_id)
  if (value.scope_id !== expectedScopeID || (binding.scopeKind === 'tenant' && value.scope_id !== binding.scopeID)) {
    throw responseInvalid()
  }
  return value
}

function validateRecord(value: unknown, zone: DNSZone): DNSRecord {
  if (!isRecordValue(value) || value.scope_id !== zone.scope_id || value.zone_id !== zone.id) {
    throw responseInvalid()
  }
  return value
}

function listItems(value: unknown): unknown[] {
  if (!isObject(value) || !exactKeys(value, ['items']) || !Array.isArray(value.items)) throw responseInvalid()
  return value.items
}

function uniqueIDs<T extends { id: string }>(items: T[]): T[] {
  if (new Set(items.map((item) => item.id)).size !== items.length) throw responseInvalid()
  return items
}

function writeHeaders(idempotencyKey: string, requestID: string, version?: number): HeadersInit {
  if (!requestIDPattern.test(idempotencyKey) || !requestIDPattern.test(requestID)) throw requestInvalid()
  return {
    'Idempotency-Key': idempotencyKey,
    ...(version === undefined ? {} : { 'If-Match': `"${version}"` }),
  }
}

export const dnsZonesApi = {
  async listZones(accessToken: string, binding: DNSZoneBinding): Promise<DNSZoneList> {
    const value = await jsonRequest(accessToken, '/v1/dns/zones', generatedRequestID('zone-list'), 200)
    const items = uniqueIDs(listItems(value).map((item) => validateZone(item, binding)))
    return { items }
  },

  async createZone(
    accessToken: string,
    input: CreateDNSZoneInput,
    idempotencyKey: string,
    binding: DNSZoneBinding,
    requestID: string,
  ): Promise<DNSZone> {
    const name = canonicalDNSZoneName(input.name)
    if (!name) throw requestInvalid()
    const canonicalInput = { ...input, name }
    const expectedScopeID = providerScope(binding, input.provider_id)
    if (input.target_scope_id !== expectedScopeID) throw responseInvalid()
    const value = validateZone(await jsonRequest(accessToken, '/v1/dns/zones', requestID, 201, {
      method: 'POST', headers: writeHeaders(idempotencyKey, requestID), body: JSON.stringify(canonicalInput),
    }), binding)
    if (value.provider_id !== canonicalInput.provider_id || value.scope_id !== canonicalInput.target_scope_id ||
      value.name !== canonicalInput.name) {
      throw responseInvalid()
    }
    return value
  },

  deleteZone(accessToken: string, zone: DNSZone, idempotencyKey: string, requestID: string): Promise<void> {
    if (!isZone(zone)) throw requestInvalid()
    return emptyRequest(accessToken, `/v1/dns/zones/${encodeURIComponent(zone.id)}`, requestID, {
      method: 'DELETE', headers: writeHeaders(idempotencyKey, requestID, zone.version),
    })
  },

  async listRecords(accessToken: string, zone: DNSZone): Promise<DNSRecordList> {
    if (!isZone(zone)) throw requestInvalid()
    const value = await jsonRequest(
      accessToken, `/v1/dns/records?zone_id=${encodeURIComponent(zone.id)}`,
      generatedRequestID('record-list'), 200,
    )
    const items = uniqueIDs(listItems(value).map((item) => validateRecord(item, zone)))
    return { items }
  },

  async createRecord(
    accessToken: string,
    input: CreateDNSRecordInput,
    idempotencyKey: string,
    zone: DNSZone,
    requestID: string,
  ): Promise<DNSRecord> {
    if (!isZone(zone)) throw requestInvalid()
    if (input.target_scope_id !== zone.scope_id || input.zone_id !== zone.id) throw responseInvalid()
    const canonicalInput = canonicalRecordInput(input)
    const value = validateRecord(await jsonRequest(accessToken, '/v1/dns/records', requestID, 201, {
      method: 'POST', headers: writeHeaders(idempotencyKey, requestID), body: JSON.stringify(canonicalInput),
    }), zone)
    if (value.name !== canonicalInput.name || value.type !== canonicalInput.type ||
      value.content !== canonicalInput.content || value.ttl !== canonicalInput.ttl) {
      throw responseInvalid()
    }
    return value
  },

  async updateRecord(
    accessToken: string,
    record: DNSRecord,
    input: UpdateDNSRecordInput,
    idempotencyKey: string,
    requestID: string,
  ): Promise<DNSRecord> {
    if (!isRecordValue(record) || input.expected_version !== record.version) throw requestInvalid()
    const canonicalInput = canonicalRecordInput(input)
    const zone = { id: record.zone_id, scope_id: record.scope_id } as DNSZone
    const value = validateRecord(await jsonRequest(
      accessToken, `/v1/dns/records/${encodeURIComponent(record.id)}`, requestID, 200, {
        method: 'PATCH', headers: writeHeaders(idempotencyKey, requestID), body: JSON.stringify(canonicalInput),
    }), zone)
    if (value.id !== record.id || value.version <= canonicalInput.expected_version || value.name !== canonicalInput.name ||
      value.type !== canonicalInput.type || value.content !== canonicalInput.content || value.ttl !== canonicalInput.ttl) {
      throw responseInvalid()
    }
    return value
  },

  deleteRecord(accessToken: string, record: DNSRecord, idempotencyKey: string, requestID: string): Promise<void> {
    if (!isRecordValue(record)) throw requestInvalid()
    return emptyRequest(accessToken, `/v1/dns/records/${encodeURIComponent(record.id)}`, requestID, {
      method: 'DELETE', headers: writeHeaders(idempotencyKey, requestID, record.version),
    })
  },
}
