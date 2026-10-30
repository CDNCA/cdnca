import { ApiError, networkApiError, responseApiError } from './auth'

export type OpenRestySecurityScopeType = 'global' | 'region' | 'node'
export type OpenRestySecurityOverrideScope = 'region' | 'node'
export type DefaultBlockWay = 'ipset' | 'exit' | 'page'
export type DefaultPageCCMode = 'force' | 'auto'
export type CCImageURLType = 'system' | 'custom'

export interface OpenRestyAutoSwitch {
  enable: boolean
  qps_50x: number
  qps_total: number
  rule: string
  seconds: number
}

export interface OpenRestyLogConfig {
  log_level: 'info' | 'debug'
  debug_ip: string
}

export interface OpenRestyInternalRule {
  period: number
  reqs: number
}

export interface OpenRestyWAFResourceLimits {
  candidate_per_param: number
  candidate_per_request: number
  ffi_per_request: number
  json_max_leaves: number
  json_max_nodes: number
  json_max_depth: number
  json_max_string_bytes: number
  json_body_bytes: number
  multipart_max_parts: number
  body_scan_bytes: number
}

export interface OpenRestySecurityConfig {
  cc_enable?: boolean
  block_time?: number
  white_time?: number
  default_block_way?: DefaultBlockWay
  ipset_auto_enable?: boolean
  site_block_qps?: number
  block_page_num_limit?: number
  block_page_not_counted?: boolean
  tmp_white_total_limit?: number
  tmp_white_per_limit?: number
  custom_white?: string
  custom_black?: string
  ssl_handshake_limit?: number
  default_page_refuse?: boolean
  force_default_page_cc?: DefaultPageCCMode
  auto_default_page_cc_qps?: number
  default_page_rule?: string
  icmp_drop?: boolean
  key?: string
  auto_delete_access_log?: 0 | 1 | 2
  auto_switch?: OpenRestyAutoSwitch
  cc_img_url_type?: CCImageURLType
  cc_img_url?: string
  at_hour?: number
  slider_html?: string
  captcha_html?: string
  click_html?: string
  delay_jump_html?: string
  rotate_html?: string
  easy_click_html?: string
  easy_slider_html?: string
  log?: OpenRestyLogConfig
  well_known_auto_protect_count?: number
  internal_qps?: number
  internal_res_block_time?: number
  internal_rule?: OpenRestyInternalRule[]
  waf_enable?: boolean
  waf_resource_limits?: OpenRestyWAFResourceLimits
}

export type OpenRestySecurityOverrideConfig = Pick<OpenRestySecurityConfig,
  'waf_enable' | 'waf_resource_limits' | 'cc_enable' | 'block_time' | 'white_time' |
  'tmp_white_total_limit' | 'tmp_white_per_limit' | 'custom_white' | 'custom_black' |
  'ssl_handshake_limit' | 'default_page_refuse' | 'default_page_rule' | 'icmp_drop' | 'key' |
  'auto_delete_access_log' | 'auto_switch' | 'slider_html' | 'captcha_html' | 'click_html' |
  'delay_jump_html' | 'rotate_html' | 'easy_click_html' | 'easy_slider_html' | 'log'>

export type OpenRestySecurityOverrideField = keyof OpenRestySecurityOverrideConfig

export interface OpenRestySecurityDocument {
  id: string
  scope_type: OpenRestySecurityScopeType
  scope_id: string
  scope_label?: string
  revision: number
  config: OpenRestySecurityConfig
  key_configured: boolean
  updated_at: string
  /** Effective documents only: the layer each config field comes from. */
  sources?: Record<string, OpenRestySecurityScopeType>
}

export interface OpenRestySecurityOverridePage {
  items: OpenRestySecurityDocument[]
  page: number
  page_size: number
  total: number
}

export interface OpenRestySecurityTarget {
  value: string
  label: string
  description?: string
}

export interface OpenRestySecurityTargetPage {
  items: OpenRestySecurityTarget[]
  page: number
  page_size: number
  total: number
}

export interface OpenRestySecurityRuleGroup {
  id: string
  name: string
  enabled: boolean
  kind?: 'system' | 'custom'
  system_rule?: boolean
  system_rule_id?: string
  system_rule_key?: string
  owner?: string
  created_at?: string
  sort?: number
}

export interface OpenRestySecurityWriteIdentity {
  requestId: string
  idempotencyKey: string
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const allConfigKeys = new Set<keyof OpenRestySecurityConfig>([
  'cc_enable', 'block_time', 'white_time', 'default_block_way', 'ipset_auto_enable',
  'site_block_qps', 'block_page_num_limit', 'block_page_not_counted', 'tmp_white_total_limit',
  'tmp_white_per_limit', 'custom_white', 'custom_black', 'ssl_handshake_limit',
  'default_page_refuse', 'force_default_page_cc', 'auto_default_page_cc_qps', 'default_page_rule',
  'icmp_drop', 'auto_delete_access_log', 'auto_switch', 'cc_img_url_type', 'cc_img_url', 'at_hour',
  'slider_html', 'captcha_html', 'click_html', 'delay_jump_html', 'rotate_html', 'easy_click_html',
  'easy_slider_html', 'log', 'well_known_auto_protect_count', 'internal_qps', 'internal_res_block_time',
  'internal_rule', 'waf_enable', 'waf_resource_limits',
])
const overrideFields = new Set<OpenRestySecurityOverrideField>([
  'waf_enable', 'waf_resource_limits', 'cc_enable', 'block_time', 'white_time',
  'tmp_white_total_limit', 'tmp_white_per_limit', 'custom_white', 'custom_black',
  'ssl_handshake_limit', 'default_page_refuse', 'default_page_rule', 'icmp_drop', 'key',
  'auto_delete_access_log', 'auto_switch', 'slider_html', 'captcha_html', 'click_html',
  'delay_jump_html', 'rotate_html', 'easy_click_html', 'easy_slider_html', 'log',
])

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exact(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key))
}

function integer(value: unknown, minimum = 0, maximum = 2_147_483_647): value is number {
  return Number.isSafeInteger(value) && Number(value) >= minimum && Number(value) <= maximum
}

function text(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length <= maximum
}

function autoSwitch(value: unknown): value is OpenRestyAutoSwitch {
  return record(value) && exact(value, ['enable', 'qps_50x', 'qps_total', 'rule', 'seconds']) &&
    typeof value.enable === 'boolean' && integer(value.qps_50x) && integer(value.qps_total) &&
    text(value.rule, 128) && integer(value.seconds)
}

function logConfig(value: unknown): value is OpenRestyLogConfig {
  return record(value) && exact(value, ['log_level', 'debug_ip']) &&
    (value.log_level === 'info' || value.log_level === 'debug') && text(value.debug_ip, 128)
}

function internalRules(value: unknown): value is OpenRestyInternalRule[] {
  return Array.isArray(value) && value.length === 3 && value.every((item) =>
    record(item) && exact(item, ['period', 'reqs']) && integer(item.period) && integer(item.reqs))
}

function wafResourceLimits(value: unknown): value is OpenRestyWAFResourceLimits {
  if (!record(value) || !exact(value, [
    'candidate_per_param', 'candidate_per_request', 'ffi_per_request', 'json_max_leaves',
    'json_max_nodes', 'json_max_depth', 'json_max_string_bytes', 'json_body_bytes',
    'multipart_max_parts', 'body_scan_bytes',
  ])) return false
  return integer(value.candidate_per_param, 256, 4096) &&
    integer(value.candidate_per_request, 1024, 16384) &&
    integer(value.ffi_per_request, 2048, 32768) &&
    integer(value.json_max_leaves, 64, 4096) &&
    integer(value.json_max_nodes, 1024, 32768) &&
    integer(value.json_max_depth, 16, 128) &&
    integer(value.json_max_string_bytes, 16 * 1024, 1024 * 1024) &&
    integer(value.json_body_bytes, 256 * 1024, 4 * 1024 * 1024) &&
    integer(value.multipart_max_parts, 16, 512) &&
    integer(value.body_scan_bytes, 1024 * 1024, 64 * 1024 * 1024) &&
    value.json_max_leaves <= value.candidate_per_param &&
    value.candidate_per_param <= value.candidate_per_request &&
    value.json_body_bytes <= value.body_scan_bytes
}

function config(value: unknown, override = false): value is OpenRestySecurityConfig {
  if (!record(value) || Object.keys(value).length < 1 || Object.hasOwn(value, 'key')) return false
  const keys = Object.keys(value) as Array<keyof OpenRestySecurityConfig>
  if (keys.some((key) => !(override ? overrideFields : allConfigKeys).has(key))) return false
  for (const [key, field] of Object.entries(value)) {
    if (['cc_enable', 'ipset_auto_enable', 'block_page_not_counted', 'default_page_refuse', 'icmp_drop', 'waf_enable'].includes(key)) {
      if (typeof field !== 'boolean') return false
    } else if (key === 'white_time') {
      if (!integer(field, 600)) return false
    } else if (['block_time', 'site_block_qps', 'block_page_num_limit', 'tmp_white_total_limit', 'tmp_white_per_limit', 'ssl_handshake_limit', 'auto_default_page_cc_qps', 'well_known_auto_protect_count', 'internal_qps', 'internal_res_block_time'].includes(key)) {
      if (!integer(field)) return false
    } else if (key === 'at_hour') {
      if (!integer(field, 0, 23)) return false
    } else if (key === 'auto_delete_access_log') {
      if (!integer(field, 0, 2)) return false
    } else if (key === 'default_block_way') {
      if (!['ipset', 'exit', 'page'].includes(String(field))) return false
    } else if (key === 'force_default_page_cc') {
      if (!['force', 'auto'].includes(String(field))) return false
    } else if (key === 'cc_img_url_type') {
      if (!['system', 'custom'].includes(String(field))) return false
    } else if (['custom_white', 'custom_black'].includes(key)) {
      if (!text(field, 1024 * 1024)) return false
    } else if (['slider_html', 'captcha_html', 'click_html', 'delay_jump_html', 'rotate_html', 'easy_click_html', 'easy_slider_html'].includes(key)) {
      if (!text(field, 2 * 1024 * 1024)) return false
    } else if (key === 'default_page_rule') {
      if (!text(field, 128)) return false
    } else if (key === 'cc_img_url') {
      if (!text(field, 2048)) return false
    } else if (key === 'auto_switch') {
      if (!autoSwitch(field)) return false
    } else if (key === 'log') {
      if (!logConfig(field)) return false
    } else if (key === 'internal_rule') {
      if (!internalRules(field)) return false
    } else if (key === 'waf_resource_limits') {
      if (!wafResourceLimits(field)) return false
    } else {
      return false
    }
  }
  return true
}

function sources(value: unknown): boolean {
  return record(value) && Object.values(value).every((source) => source === 'global' || source === 'region' || source === 'node')
}

function effectiveDocument(value: unknown): value is OpenRestySecurityDocument {
  if (!record(value) || !sources(value.sources)) return false
  const { sources: _sources, ...rest } = value
  return document(rest)
}

function document(value: unknown, override = false): value is OpenRestySecurityDocument {
  if (!record(value) || !exact(value, ['id', 'scope_type', 'scope_id', 'revision', 'config', 'key_configured', 'updated_at'], ['scope_label'])) return false
  if (typeof value.id !== 'string' || !uuidPattern.test(value.id) ||
    !['global', 'region', 'node'].includes(String(value.scope_type)) ||
    typeof value.scope_id !== 'string' || value.scope_id.length < 1 || value.scope_id.length > 64 ||
    !integer(value.revision, 0, Number.MAX_SAFE_INTEGER) || !config(value.config, override) ||
    typeof value.key_configured !== 'boolean' || typeof value.updated_at !== 'string' || !Number.isFinite(Date.parse(value.updated_at))) return false
  return value.scope_label === undefined || typeof value.scope_label === 'string' && value.scope_label.length >= 1 && value.scope_label.length <= 128
}

function overridePage(value: unknown): value is OpenRestySecurityOverridePage {
  return record(value) && exact(value, ['items', 'page', 'page_size', 'total']) &&
    Array.isArray(value.items) && value.items.every((item) => document(item, true)) &&
    integer(value.page, 1) && integer(value.page_size, 1, 100) && integer(value.total)
}

function targetPage(value: unknown): value is OpenRestySecurityTargetPage {
  return record(value) && exact(value, ['items', 'page', 'page_size', 'total']) &&
    Array.isArray(value.items) && value.items.every((item) => record(item) && exact(item, ['value', 'label'], ['description']) &&
      typeof item.value === 'string' && item.value.length >= 1 && item.value.length <= 128 &&
      typeof item.label === 'string' && item.label.length >= 1 && item.label.length <= 128 &&
      (item.description === undefined || typeof item.description === 'string' && item.description.length <= 256)) &&
    integer(value.page, 1) && integer(value.page_size, 1, 100) && integer(value.total)
}

export interface OpenRestySecurityRuleGroupSummary {
  all: number
  system: number
  custom: number
  visible: number
  disabled: number
}

const ruleGroupSummaryKeys = ['all', 'system', 'custom', 'visible', 'disabled'] as const

function ruleGroups(value: unknown): value is OpenRestySecurityRuleGroup[] {
  return Array.isArray(value) && value.every((item) => record(item) && exact(item, ['id', 'name', 'enabled', 'kind', 'system_rule'], ['system_rule_id', 'system_rule_key', 'owner', 'created_at', 'sort']) &&
    typeof item.id === 'string' && item.id.length >= 1 && item.id.length <= 128 &&
    typeof item.name === 'string' && item.name.length >= 1 && item.name.length <= 128 && typeof item.enabled === 'boolean' &&
    (item.kind === 'system' || item.kind === 'custom') && typeof item.system_rule === 'boolean' &&
    (item.system_rule_id === undefined || text(item.system_rule_id, 32)) &&
    (item.system_rule_key === undefined || text(item.system_rule_key, 128)) &&
    (item.owner === undefined || text(item.owner, 128)) &&
    (item.created_at === undefined || typeof item.created_at === 'string' && Number.isFinite(Date.parse(item.created_at))) &&
    (item.sort === undefined || integer(item.sort, 1, 10000)))
}

function invalidResponse(): ApiError {
  return new ApiError('Invalid OpenResty security response', 0, 'invalid_response')
}

async function request<T>(token: string, path: string, validate: (value: unknown) => value is T, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${token}`,
        'X-Request-ID': crypto.randomUUID(),
        ...(init.body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  let body: unknown
  try { body = await response.json() } catch { throw invalidResponse() }
  if (!validate(body)) throw invalidResponse()
  return body
}

async function requestEmpty(token: string, path: string, status: number, init: RequestInit): Promise<void> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: { Authorization: `Bearer ${token}`, 'X-Request-ID': crypto.randomUUID(), ...init.headers },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) throw await responseApiError(response)
  if (response.status !== status) throw invalidResponse()
}

export function newOpenRestySecurityIdentity(prefix = 'openresty-security'): OpenRestySecurityWriteIdentity {
  const suffix = crypto.randomUUID()
  return { requestId: `${prefix}-${suffix}`, idempotencyKey: `${prefix}-${suffix}` }
}

function writeHeaders(identity: OpenRestySecurityWriteIdentity, revision?: number): Record<string, string> {
  return {
    'X-Request-ID': identity.requestId,
    'Idempotency-Key': identity.idempotencyKey,
    ...(revision === undefined ? {} : { 'If-Match': `"${revision}"` }),
  }
}

export const openrestySecurityApi = {
  getGlobal(token: string): Promise<OpenRestySecurityDocument> {
    return request(token, '/v1/openresty-security/configs/global', (value): value is OpenRestySecurityDocument => document(value))
  },
  patchGlobal(token: string, revision: number, patch: OpenRestySecurityConfig, identity = newOpenRestySecurityIdentity('openresty-global')): Promise<OpenRestySecurityDocument> {
    return request(token, '/v1/openresty-security/configs/global', (value): value is OpenRestySecurityDocument => document(value), {
      method: 'PATCH', headers: writeHeaders(identity, revision), body: JSON.stringify({ patch }),
    })
  },
  listOverrides(token: string, input: { scopeType?: OpenRestySecurityOverrideScope; query?: string; page?: number; pageSize?: number } = {}): Promise<OpenRestySecurityOverridePage> {
    const query = new URLSearchParams({ page: String(input.page ?? 1), page_size: String(input.pageSize ?? 20) })
    if (input.scopeType) query.set('scope_type', input.scopeType)
    if (input.query?.trim()) query.set('query', input.query.trim())
    return request(token, `/v1/openresty-security/overrides?${query}`, overridePage)
  },
  createOverride(token: string, input: { scopeType: OpenRestySecurityOverrideScope; scopeId: string; config: OpenRestySecurityOverrideConfig }, identity = newOpenRestySecurityIdentity('openresty-override-create')): Promise<OpenRestySecurityDocument> {
    return request(token, '/v1/openresty-security/overrides', (value): value is OpenRestySecurityDocument => document(value, true), {
      method: 'POST', headers: writeHeaders(identity, 0),
      body: JSON.stringify({ scope_type: input.scopeType, scope_id: input.scopeId, config: input.config }),
    })
  },
  patchOverride(token: string, input: { id: string; revision: number; patch: OpenRestySecurityOverrideConfig; removedFields?: OpenRestySecurityOverrideField[] }, identity = newOpenRestySecurityIdentity('openresty-override-patch')): Promise<OpenRestySecurityDocument> {
    return request(token, `/v1/openresty-security/overrides/${encodeURIComponent(input.id)}`, (value): value is OpenRestySecurityDocument => document(value, true), {
      method: 'PATCH', headers: writeHeaders(identity, input.revision),
      body: JSON.stringify({ patch: input.patch, ...(input.removedFields?.length ? { removed_fields: input.removedFields } : {}) }),
    })
  },
  deleteOverride(token: string, input: { id: string; revision: number }, identity = newOpenRestySecurityIdentity('openresty-override-delete')): Promise<void> {
    return requestEmpty(token, `/v1/openresty-security/overrides/${encodeURIComponent(input.id)}`, 204, {
      method: 'DELETE', headers: writeHeaders(identity, input.revision),
    })
  },
  /** A node's effective config and the layer (global / region / node) of each field. */
  getEffective(token: string, nodeId: string): Promise<OpenRestySecurityDocument> {
    return request(token, `/v1/openresty-security/effective?${new URLSearchParams({ node_id: nodeId })}`, effectiveDocument)
  },
  searchTargets(token: string, input: { scopeType: OpenRestySecurityOverrideScope; query?: string; page?: number; pageSize?: number }): Promise<OpenRestySecurityTargetPage> {
    const query = new URLSearchParams({ scope_type: input.scopeType, page: String(input.page ?? 1), page_size: String(input.pageSize ?? 20) })
    if (input.query?.trim()) query.set('query', input.query.trim())
    return request(token, `/v1/openresty-security/targets?${query}`, targetPage)
  },
  listRuleGroups(token: string): Promise<OpenRestySecurityRuleGroup[]> {
    return request(token, '/v1/cc-rule-groups', ruleGroups)
  },
  /** 规则组胶囊 counts over every group (system from the synced catalog, else the projection). */
  ruleGroupSummary(token: string): Promise<OpenRestySecurityRuleGroupSummary> {
    return request(token, '/v1/cc-rule-groups/summary', (value): value is OpenRestySecurityRuleGroupSummary =>
      record(value) && exact(value, ruleGroupSummaryKeys) && ruleGroupSummaryKeys.every((key) => integer(value[key])))
  },
  setRuleGroupEnabled(token: string, id: string, enabled: boolean): Promise<{ id: string; enabled: boolean }> {
    return request(token, `/v1/cc-rule-groups/${encodeURIComponent(id)}/${enabled ? 'enable' : 'disable'}`, (value): value is { id: string; enabled: boolean } => {
      if (!record(value) || !exact(value, ['id', 'enabled']) || typeof value.id !== 'string' || typeof value.enabled !== 'boolean') return false
      return value.id === id && value.enabled === enabled
    }, { method: 'POST' })
  },
  queueCCImageDownload(token: string, identity = newOpenRestySecurityIdentity('openresty-cc-image')): Promise<void> {
    return requestEmpty(token, '/v1/openresty-security/actions/download-cc-image', 202, {
      method: 'POST', headers: writeHeaders(identity),
    })
  },
}
