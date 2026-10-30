import { ApiError, networkApiError, responseApiError } from './auth'

export type SecurityPolicyKind = 'cc' | 'acl' | 'waf'
export type SecurityPolicyDecision = 'allow' | 'block'
export type SecurityPolicyAction = SecurityPolicyDecision | 'rate_limit' | 'challenge' | 'log' | 'managed_waf' | 'ban'
export type SecurityPolicyFlow = 'continue' | 'stop'

export interface SecurityPolicyCondition {
  field: 'client_ip' | 'host' | 'path' | 'method' | 'header' | 'country' | 'asn' | 'ja4' | 'port' | 'distinct_user_agents' | 'status_404_count'
    | 'args' | 'query' | 'body' | 'request_uri' | 'cookie' | 'user_agent' | 'referer'
    | 'carrier' | 'ip_tag' | 'province' | 'city'
    | 'upload_filename' | 'upload_extension' | 'header_names'
    // Node WAF v4: Content-Type, HTTP version, named IP list.
    | 'content_type' | 'http_version' | 'ip_list'
    | 'request_length' | 'body_length' | 'uri_length' | 'header_max_length' | 'header_count' | 'arg_count'
    // Node WAF v5: multipart part names, part count, longest field.
    | 'multipart_field_names' | 'multipart_part_count' | 'multipart_field_max_length'
  operator: string
  key?: string
  values: string[]
  /** WAF content fields: transforms applied in order (length last, with a number_* operator). */
  filters?: SecurityPolicyWAFFilter[]
  /** WAF body fields: 'match' makes the condition hold for a body over the 64 KiB inspection limit. */
  body_overflow?: 'match'
}

export type SecurityPolicyWAFFilter = 'lowercase' | 'base64_decode' | 'unicode_decode' | 'html_unescape' | 'length'

/** WAF observe mode and auto block (node WAF v2). */
export interface SecurityPolicyWAFSettings {
  mode?: '' | 'observe'
  auto_block?: { window_seconds: number; hit_threshold: number; block_seconds: number }
}

export interface SecurityPolicyRule {
  id?: string
  name: string
  priority: number
  enabled: boolean
	comment?: string
	expires_at?: string
  conditions: SecurityPolicyCondition[]
  action: SecurityPolicyAction
  flow: SecurityPolicyFlow
  action_config: {
    rate_limit?: { window_seconds: number; max_requests: number; max_requests_per_uri?: number; algorithm?: string; response_action?: string; ban_seconds?: number }
    challenge?: SecurityPolicyChallengeConfig
    managed_waf?: SecurityPolicyManagedWAF
    /** WAF ban: block the client for ban_seconds (node WAF v2). */
    waf_ban?: { ban_seconds: number }
    /** WAF challenge: proof-of-work page (POST answered 307) and pass cookie lifetime (node WAF v2). */
    waf_challenge?: { pass_seconds: number; pow_bits: number }
  }
  /** CC only (node CC v4): one or two keys counted together; absent = client IP. */
  count_by?: SecurityPolicyCountKey[]
  /** CC temporary ban with count_by: ban the counted bucket instead of the client. */
  action_target?: 'count_key'
}

export type SecurityPolicyCountKeyName = 'client_ip' | 'client_cidr' | 'host' | 'uri' | 'uri_path' | 'ja4'
  // CC v7: header / cookie / query carry a name.
  | 'user_agent' | 'referer' | 'header' | 'cookie' | 'query'

export interface SecurityPolicyCountKey {
  key: SecurityPolicyCountKeyName
  ipv4_prefix?: number
  ipv6_prefix?: number
  /** header (stored lower case) / cookie / query argument name (CC v7). */
  name?: string
}

export interface CatalogDuplicate { group_key: string; rule: string; same_as: string }
export interface CatalogConflict { group_key: string; rule: string; with: string }

export interface CatalogRuleSet {
  rules: SecurityPolicyRule[]
  duplicates?: CatalogDuplicate[]
  conflicts?: CatalogConflict[]
  /** keys=@system-default (WAF): the system default WAF switch and settings. */
  default?: { enabled: boolean; rules: SecurityPolicyRule[]; waf_settings?: SecurityPolicyWAFSettings }
}

/** catalog-rules key of the system default WAF (系统设置 > 网站默认 > 安全设置). */
export const systemDefaultWAFKey = '@system-default'

/** Verification page parameters (securitypolicy.ChallengeConfig); all come from the catalog or the operator. */
export interface SecurityPolicyChallengeConfig {
  type: string
  failure_window_seconds?: number
  max_failures?: number
  pass_seconds?: number
  ban_seconds?: number
  log_only?: boolean
  pow_bits?: number
  delay_seconds?: number
  challenge_seconds?: number
  bind_ipv4_prefix?: number
  bind_ipv6_prefix?: number
  key_rotate_seconds?: number
  trigger_window_seconds?: number
  trigger_max_requests?: number
  pass_window_seconds?: number
  pass_max_requests?: number
  pass_max_requests_per_uri?: number
}

/**
 * Managed WAF (OWASP CRS on libmodsecurity, securitypolicy.ManagedWAFConfig):
 * a CRS profile pack (system/crs-<level>: rule sets, paranoia, threshold and
 * action fixed by the pack) plus the scoring rule IDs the sites do not
 * evaluate (from the profile's exports) and the engine limits.
 */
export interface SecurityPolicyManagedWAF {
  request_body_limit: number
  request_body_no_files_limit: number
  request_body_limit_action: 'reject' | 'partial'
  arguments_limit: number
  json_depth_limit: number
  pcre_match_limit: number
  /** Inspection limit hit (regex step limit, more than 100 request headers): omitted = log only. */
  inspection_limit_action?: 'log' | 'block'
  /** CRS profile pack ID, system/crs-pl1 by default. */
  profile: string
  exclusions?: number[]
}

/** A CRS profile pack this control plane downloaded (GET /v1/sites/{id}/crs). */
export interface CRSProfilePack {
  pack_id: string
  version: string
  name: string
  description: string
  /** Rule IDs a site may exclude. */
  exports: number[]
  /** The profile as a protection tier, counted from the CRS rule text (null until it is synced). */
  tier?: CRSTier | null
}

/** One attack class (CRS rule set) of a tier; excluding all its rules turns it off. */
export interface CRSTierSet {
  key: string
  name: string
  paranoia: number
  rules_by_paranoia: Record<string, number>
  rules: number[]
}

/** What a tier adds to the next narrower one (rulepack.CRSTierAddition). */
export interface CRSTierAddition {
  kind: 'set' | 'paranoia' | 'block'
  key?: string
  name?: string
  from_paranoia?: number
  to_paranoia?: number
  rules: number
}

/** WAF protection tier (仅记录 / 标准防护 / 严格防护 / 极严格防护, strictly increasing). */
export interface CRSTier {
  pack_id: string
  name: string
  order: number
  action: 'log' | 'block'
  paranoia: number
  sets: CRSTierSet[]
  previous: string
  added: CRSTierAddition[]
}

/** A site's own CRS settings: each item null to inherit the WAF rule library's managed WAF. */
export interface SiteCRSOverride {
  profile: string | null
  exclusions: number[] | null
  /** Application types (application exclusion packs system/app-<key>); site only, none by default. */
  apps?: string[]
}

/** A selectable application type (OWASP CRS official application exclusion plugin). */
export interface CRSAppSummary {
  pack_id: string
  key: string
  name: string
  version: string
  description: string
}

export interface SiteCRSValues {
  policy_id: string
  version: number
  profile: string
  exclusions: number[]
}

export interface SiteCRSState {
  site_id: string
  /** Site version (ETag / If-Match). */
  version: number
  override: SiteCRSOverride
  /** The managed WAF of the site's WAF rule library; null when it runs none. */
  library: SiteCRSValues | null
  effective: SiteCRSValues | null
  profiles: CRSProfilePack[]
  apps: CRSAppSummary[]
  updated_at: string | null
  /** ModSecurity rule pack mounts suspended because the effective profile does not cover them. */
  rule_pack_suspensions: RulePackSuspension[]
  /** Update responses only: what this write suspended and restored. */
  rule_pack_change?: { suspended: RulePackSuspension[]; restored: RulePackSuspension[] }
}

export interface RulePackSuspension {
  pack_id: string
  version: string
  reason: 'out_of_profile'
  /** '' = the site runs no managed WAF. */
  crs_profile: string
  detail: string
  suspended_at: string
}

/** Site-level ban / pass duration: system follows 全局 CC 配置, custom is the value (resolved seconds either way). */
export interface SecurityPolicyCCDuration {
  mode: 'system' | 'custom'
  seconds: number
}

/**
 * 自动切换 (CC API v5): at qps_total requests (or qps_5xx origin 5xx responses)
 * per second on a node the site runs `rules` until both stayed below for
 * recover_seconds. system follows the global auto switch (resolved by the
 * server; no rules = off).
 */
export interface SecurityPolicyCCAutoSwitch {
  mode: 'system' | 'custom'
  qps_total: number
  qps_5xx: number
  recover_seconds: number
  rule_groups: string[]
  rules: SecurityPolicyRule[]
}

/**
 * 蜘蛛白名单 (CC API v6): a request whose User-Agent contains one of the
 * tokens is the crawler when the client is in `networks` or its address
 * forward-confirms (reverse DNS) under one of `rdns_suffixes`; it then skips
 * every CC rule, ban and challenge. A token alone never trusts.
 */
export interface SecurityPolicyCCTrustedCrawler {
  name: string
  user_agent_tokens: string[]
  networks?: string[]
  rdns_suffixes?: string[]
}

export interface SecurityPolicyCCSettings {
  ban_seconds?: SecurityPolicyCCDuration
  pass_seconds?: SecurityPolicyCCDuration
  auto_switch?: SecurityPolicyCCAutoSwitch
  trusted_crawlers?: SecurityPolicyCCTrustedCrawler[]
  /** The pass cookie's Domain (CC API v6), shared by the site's subdomains. */
  challenge_cookie_domain?: string
}

export interface SecurityPolicyFields {
  kind: SecurityPolicyKind
  name: string
  description: string
  enabled: boolean
  default_action: SecurityPolicyDecision
	acl_import?: string
  rules: SecurityPolicyRule[]
  /** CC only: site-level settings; a full update must send them back (omitting clears them). */
  cc_settings?: SecurityPolicyCCSettings
  /** WAF only: observe mode and auto block; a full update must send them back. */
  waf_settings?: SecurityPolicyWAFSettings
}

/** IP intelligence library carrier tags a quick block can block. */
export const quickBlockCarriers = [
  'carrier:cn-telecom', 'carrier:cn-unicom', 'carrier:cn-mobile', 'carrier:cn-cernet',
  'carrier:cn-cstnet', 'carrier:cn-drpeng', 'carrier:cn-cbn',
] as const
export type QuickBlockCarrier = typeof quickBlockCarriers[number]

/** A trusted crawler: requests from one of the networks whose User-Agent starts with a prefix (the WAF geo contract). */
export interface QuickBlockCrawler {
  networks: string[]
  user_agent_prefixes: string[]
}

/**
 * WAF quick block switches (站点“防护”页快速屏蔽). They expand to
 * system-managed rules that lead the policy (isQuickBlockRuleID); only
 * setQuickBlock changes them.
 */
export interface SecurityPolicyQuickBlock {
  block_idc_cn: boolean
  block_idc_global: boolean
  carriers: QuickBlockCarrier[]
  allowed_crawlers: QuickBlockCrawler[]
}

/**
 * A site's own quick block: each item null to inherit
 * the site's WAF rule library, or the site's value. Lists replace the
 * library's as a whole; [] is off.
 */
export interface SiteQuickBlockOverride {
  block_idc_cn: boolean | null
  block_idc_global: boolean | null
  carriers: QuickBlockCarrier[] | null
  allowed_crawlers: QuickBlockCrawler[] | null
}

export interface SiteQuickBlockState {
  site_id: string
  /** Site version (ETag / If-Match). */
  version: number
  override: SiteQuickBlockOverride
  /** The site's WAF rule library; null when none is bound. */
  library: {
    policy_id: string
    version: number
    active_version: number
    /** The library can carry a quick block that blocks anything. */
    supported: boolean
    quick_block: SecurityPolicyQuickBlock
  } | null
  effective: SecurityPolicyQuickBlock | null
  updated_at: string | null
}

export interface SecurityPolicy extends SecurityPolicyFields {
  id: string
  scope_id: string
  owner?: { id: string; display_name: string }
  version: number
  created_at: string
  updated_at: string
  /** WAF only: the quick block switches (read only; absent when never configured). */
  quick_block?: SecurityPolicyQuickBlock
  /** Subscribed rule libraries are protected (no rules, read only). */
  protected?: boolean
  /** Subscribed WAF copies: the platform library (GET /v1/waf-rule-libraries id) it was copied from. */
  library_id?: string
}

/**
 * Whether a rule ID is one of the quick block's reserved, system-managed
 * rule IDs (control-api securitypolicy.QuickBlockRuleID: the first 32 bits
 * zero, a slot 1..34, version 5).
 */
export function isQuickBlockRuleID(id: string | undefined): boolean {
  const match = /^00000000-([0-9a-f]{4})-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.exec(id ?? '')
  if (!match) return false
  const slot = Number.parseInt(match[1]!, 16)
  return slot >= 1 && slot <= 34
}

export interface IPIntelStatus {
  ready: boolean
  revision: number
}

export interface SecurityPolicyList {
  items: SecurityPolicy[]
  total: number
  page: number
  limit: number
  /** Policies under every filter but status, over every page (the server always sends it). */
  counts?: { all: number; enabled: number; disabled: number }
}

export type SecurityPolicyReferenceKind = 'matcher' | 'filter'

export interface SecurityPolicyReference {
  id: string
  scope_id: string
  owner?: { id: string; display_name: string }
  name: string
  system_rule: boolean
  system_rule_id?: string
  system_rule_key?: string
  status: 'enabled' | 'disabled'
  type?: string
  sort?: number
  created_at: string
  policy_id?: string
  rule_id?: string
  field?: string
  operator?: string
  values?: string[]
  key?: string
  description?: string
  version?: number
  updated_at?: string
  parameters?: Record<string, unknown>
}

export interface SecurityPolicyReferenceList {
  items: SecurityPolicyReference[]
  total: number
  page: number
  limit: number
}

export interface SecurityPolicyReferenceFilters {
  page: number
  limit: number
  status?: 'enabled' | 'disabled'
  type?: string
  name?: string
  id?: string
  owner?: string
}

export interface SecurityPolicyMatcherFields {
  name: string
  description: string
  enabled: boolean
  field: string
  operator: string
  key?: string
  values: string[]
}

export interface SecurityPolicyFilterFields {
  name: string
  description: string
  enabled: boolean
  type: string
  parameters: Record<string, unknown>
}

export interface SecurityPolicyFilters {
  page: number
  limit: number
  kind?: SecurityPolicyKind
  status?: 'enabled' | 'disabled'
  name?: string
  id?: string
  owner?: string
  /** SEC-ACCOUNT-04（仅 WAF）：global 未绑站点的自建库、site 已绑站点的自建库、system 平台库副本；服务端筛选。 */
  scope?: SecurityPolicyScope
}

export type SecurityPolicyScope = 'global' | 'site' | 'system'
export type SecurityPolicyBatchAction = 'enable' | 'disable' | 'delete'
export type SecurityPolicyBatchStatus =
  | 'ok' | 'unchanged' | 'version_conflict' | 'system_protected' | 'not_found' | 'forbidden' | 'in_use'
  | 'unsupported_kind' | 'idempotency_conflict' | 'rejected' | 'error' | 'not_attempted'

export interface SecurityPolicyBatchResult {
  id: string
  status: SecurityPolicyBatchStatus
  version?: number
  replayed?: boolean
}

export interface RequestFacts {
  client_ip: string
  host: string
  path: string
  method: string
  headers: Record<string, string[]>
  country: string
  asn: number
  ja4: string
  port: number
  distinct_user_agents: number
  status_404_count: number
}

export function parsePreviewHeaders(value: string): Record<string, string[]> {
  const result: Record<string, string[]> = {}
  let count = 0
  for (const rawLine of value.split('\n')) {
    const line = rawLine.trim()
    if (!line) continue
    const separator = line.indexOf(':')
    const name = line.slice(0, separator).trim().toLowerCase()
    const headerValue = line.slice(separator + 1).trim()
    const invalidValue = [...headerValue].some((character) => {
      const code = character.charCodeAt(0)
      return code < 0x20 || code === 0x7f
    })
    if (separator < 1 || !/^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/.test(name) || !headerValue || headerValue.length > 4096 || invalidValue || ++count > 100) {
      throw new Error('invalid preview headers')
    }
    ;(result[name] ??= []).push(headerValue)
  }
  return result
}

export interface SecurityPolicyEvaluation {
  policy_id: string
  policy_version: number
  action: SecurityPolicyAction
  matched_rule_ids: string[]
	expired_rule_ids?: string[]
  terminal_rule_id?: string
  used_default: boolean
}

export interface SecurityPolicyImportLineError {
	line: number
	code: string
}

export class SecurityPolicyImportApiError extends ApiError {
	readonly lineErrors: SecurityPolicyImportLineError[]

	constructor(requestId: string | undefined, lineErrors: SecurityPolicyImportLineError[]) {
		super('ACL import contains invalid lines', 422, 'acl_import_invalid', requestId)
		this.name = 'SecurityPolicyImportApiError'
		this.lineErrors = lineErrors
	}
}

export type SecurityActivationCandidateStatus =
  | 'claimed'
  | 'canary'
  | 'expanding'
  | 'healthy'
  | 'failed'
  | 'cancelled'
  | 'expired'
  | 'promoted'

export interface SecurityActivationBinding {
  id: string
  policy_id: string
  binding_revision: number
  active_policy_version: number
  last_claimed_policy_version: number
}

export interface SecurityActivationCandidate {
  id: string
  tenant_scope_id: string
  site_id: string
  binding_id: string
  binding_revision: number
  last_bundle_id: string
  last_claimed_policy_version: number
  expected_active_policy_version: number
  candidate_source_revision: number
  candidate_config_version_id: string
  candidate_artifact_sha256: number[]
  target_snapshot_sha256: number[]
  required_capabilities: Array<{ name: number; api_version: number }>
  candidate_status: SecurityActivationCandidateStatus
  canary_node_ids: string[]
  expand_node_ids: string[]
  expires_at: string
  created_at: string
  updated_at: string
  recovered_at?: string
}

/** P11: one failed node. node_name/node_ip are "" when unknown; reason is a stable cause code (sec-ui-polish). */
export interface SecurityActivationFailureReason {
  node_id: string
  node_name: string
  node_ip: string
  phase: string
  code?: string
  reason?: 'waf_engine_unavailable'
  message: string
}

export interface SecurityActivationStatus {
  binding: SecurityActivationBinding | null
  latest_candidate: SecurityActivationCandidate | null
  operation: 'activation' | 'rollback' | null
  /** A release refused for node capability, published automatically once the nodes are upgraded. */
  capability_wait?: {
    /** rule_pack: waiting for the nodes to apply the site's rule packs (sa-rulepack-wait). */
    wait_kind?: 'capability' | 'rule_pack'
    node_ids: string[]; required_cc_version: number; rule_packs?: string[]; policy_version: number; created_at: string
  }
  /** P11: when latest_candidate failed, each failed node's own failure text. */
  failure_reasons?: SecurityActivationFailureReason[]
  /** sec-rebind: the latest candidate withdraws the site's library of this kind. */
  latest_detach?: boolean
  /** sec-rebind: whether the latest promotion can be rolled back, to what, or why not. */
  rollback?: SecurityActivationRollbackAvailability
}

export interface SecurityActivationRollbackAvailability {
  available: boolean
  reason?: 'no_candidate' | 'in_flight' | 'no_previous' | 'previous_policy_deleted'
  candidate_id?: string
  policy_id?: string
  source_policy_version?: number
}

export interface SecurityActivationPublishInput {
  site_id: string
  policy_id: string
  policy_version: number
  expected_binding_revision: number
  expected_active_policy_version: number
  target_node_ids: string[]
  canary_size: number
  expires_at: string
  /** sec-rebind: withdraw the site's active library (policy_id/policy_version are the binding's active ones). */
  detach?: boolean
}

export interface SecurityActivationPromotionCAS {
  tenant_scope_id: string
  binding_id: string
  binding_revision: number
  last_bundle_id: string
  last_claimed_policy_version: number
  expected_active_policy_version: number
  candidate_source_revision: number
  candidate_config_version_id: string
  candidate_artifact_sha256: number[]
  target_snapshot_sha256: number[]
}

export interface SecurityActivationRollbackInput {
  source_policy_version: number
  expected_binding_revision: number
  expected_active_policy_version: number
  target_node_ids: string[]
  canary_size: number
  expires_at: string
}

export interface SecurityActivationWriteMetadata {
  requestId: string
  idempotencyKey: string
  traceparent: string
  correlationId?: string
  taskId?: string
}

export interface SecurityActivationStartResult {
  candidate: SecurityActivationCandidate
  replayed?: boolean
}

export interface SecurityActivationReconcileResult extends SecurityActivationStartResult {
  action: '' | 'wait' | 'expand' | 'promote' | 'recover' | 'fail' | 'cancel' | 'expire'
}

const apiRoot = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function request<T>(accessToken: string, path: string, init: RequestInit = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiRoot}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    })
  } catch {
    throw networkApiError()
  }
  if (!response.ok) {
		if (response.status === 422) {
			const body = await response.clone().json().catch(() => null) as {
				error?: { code?: unknown; request_id?: unknown; line_errors?: unknown }
			} | null
			if (body?.error?.code === 'acl_import_invalid' && Array.isArray(body.error.line_errors)) {
				const lineErrors = body.error.line_errors.filter((item): item is SecurityPolicyImportLineError => {
					if (!item || typeof item !== 'object') return false
					const candidate = item as Record<string, unknown>
					return Number.isSafeInteger(candidate.line) && Number(candidate.line) > 0 &&
						typeof candidate.code === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(candidate.code)
				})
				const requestId = typeof body.error.request_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.error.request_id)
					? body.error.request_id
					: undefined
				throw new SecurityPolicyImportApiError(requestId, lineErrors)
			}
		}
    throw await responseApiError(response)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function query(filters: SecurityPolicyFilters): string {
  const values = new URLSearchParams({ page: String(filters.page), limit: String(filters.limit) })
  if (filters.kind) values.set('kind', filters.kind)
  if (filters.status) values.set('status', filters.status)
  if (filters.name) values.set('name', filters.name)
  if (filters.id) values.set('id', filters.id)
  if (filters.owner) values.set('owner', filters.owner)
  if (filters.scope) values.set('scope', filters.scope)
  return values.toString()
}

function writeHeaders(idempotencyKey: string, version?: number): HeadersInit {
  return {
    'Idempotency-Key': idempotencyKey,
    ...(version ? { 'If-Match': `"${version}"` } : {}),
  }
}

function list(accessToken: string, filters: SecurityPolicyFilters): Promise<SecurityPolicyList> {
  return request(accessToken, `/v1/security-policies?${query(filters)}`)
}

function listReferences(
  accessToken: string,
  kind: SecurityPolicyReferenceKind,
  filters: SecurityPolicyReferenceFilters,
): Promise<SecurityPolicyReferenceList> {
  const values = new URLSearchParams({ page: String(filters.page), limit: String(filters.limit) })
  if (filters.status) values.set('status', filters.status)
  if (filters.type) values.set('type', filters.type)
  if (filters.name) values.set('name', filters.name)
  if (filters.id) values.set('id', filters.id)
  if (filters.owner) values.set('owner', filters.owner)
  return request(accessToken, `/v1/security-policies/${kind === 'matcher' ? 'matchers' : 'filters'}?${values}`)
}

function createReference(
  accessToken: string,
  kind: SecurityPolicyReferenceKind,
  input: (SecurityPolicyMatcherFields | SecurityPolicyFilterFields) & { target_scope_id?: string; owner_id?: string },
  idempotencyKey: string,
): Promise<SecurityPolicyReference> {
  return request(accessToken, `/v1/security-policies/${kind === 'matcher' ? 'matchers' : 'filters'}`, {
    method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input),
  })
}

function updateReference(
  accessToken: string,
  kind: SecurityPolicyReferenceKind,
  id: string,
  version: number,
  input: SecurityPolicyMatcherFields | SecurityPolicyFilterFields,
  idempotencyKey: string,
): Promise<SecurityPolicyReference> {
  return request(accessToken, `/v1/security-policies/${kind === 'matcher' ? 'matchers' : 'filters'}/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: writeHeaders(idempotencyKey, version), body: JSON.stringify(input),
  })
}

function removeReference(accessToken: string, kind: SecurityPolicyReferenceKind, id: string, version: number, idempotencyKey: string): Promise<void> {
  return request(accessToken, `/v1/security-policies/${kind === 'matcher' ? 'matchers' : 'filters'}/${encodeURIComponent(id)}`, {
    method: 'DELETE', headers: writeHeaders(idempotencyKey, version),
  })
}

function setReferenceEnabled(
  accessToken: string,
  kind: SecurityPolicyReferenceKind,
  id: string,
  version: number,
  enabled: boolean,
  idempotencyKey: string,
): Promise<SecurityPolicyReference> {
  return request(accessToken, `/v1/security-policies/${kind === 'matcher' ? 'matchers' : 'filters'}/${encodeURIComponent(id)}/${enabled ? 'enable' : 'disable'}`, {
    method: 'POST', headers: writeHeaders(idempotencyKey, version),
  })
}

/**
 * Rules built server-side from the synced system catalog (every value from the
 * catalog). scopeID is the policy's target scope (administrators).
 */
function catalogRules(accessToken: string, kind: 'waf' | 'cc', keys: string[], scopeID?: string): Promise<CatalogRuleSet> {
  const scope = scopeID ? `&scope_id=${encodeURIComponent(scopeID)}` : ''
  return request(accessToken, `/v1/security-policies/catalog-rules?kind=${kind}&keys=${keys.map(encodeURIComponent).join(',')}${scope}`)
}

function create(
  accessToken: string,
  input: SecurityPolicyFields & { target_scope_id?: string; owner_id?: string },
  idempotencyKey: string,
): Promise<SecurityPolicy> {
  return request(accessToken, '/v1/security-policies', {
    method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify(input),
  })
}

function update(
  accessToken: string, id: string, version: number, input: SecurityPolicyFields,
  idempotencyKey: string,
): Promise<SecurityPolicy> {
  return request(accessToken, `/v1/security-policies/${encodeURIComponent(id)}`, {
    method: 'PATCH', headers: writeHeaders(idempotencyKey, version), body: JSON.stringify(input),
  })
}

// SEC-ACCOUNT-04: one CAS write per item (id + version); one result per item in request order.
function batch(
  accessToken: string, action: SecurityPolicyBatchAction, items: Array<{ id: string; version: number }>,
  idempotencyKey: string,
): Promise<{ items: SecurityPolicyBatchResult[] }> {
  return request(accessToken, '/v1/security-policies/batch', {
    method: 'POST', headers: writeHeaders(idempotencyKey), body: JSON.stringify({ action, items }),
  })
}

function remove(
  accessToken: string, id: string, version: number, idempotencyKey: string,
): Promise<void> {
  return request(accessToken, `/v1/security-policies/${encodeURIComponent(id)}`, {
    method: 'DELETE', headers: writeHeaders(idempotencyKey, version),
  })
}

function setQuickBlock(
  accessToken: string, id: string, version: number, input: SecurityPolicyQuickBlock, idempotencyKey: string,
): Promise<SecurityPolicy> {
  return request(accessToken, `/v1/security-policies/${encodeURIComponent(id)}/quick-block`, {
    method: 'PUT', headers: writeHeaders(idempotencyKey, version), body: JSON.stringify(input),
  })
}

function getSiteQuickBlock(accessToken: string, siteID: string, signal?: AbortSignal): Promise<SiteQuickBlockState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/quick-block`, { signal })
}

function setSiteQuickBlock(
  accessToken: string, siteID: string, siteVersion: number, input: SiteQuickBlockOverride, idempotencyKey: string,
): Promise<SiteQuickBlockState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/quick-block`, {
    method: 'PUT', headers: writeHeaders(idempotencyKey, siteVersion), body: JSON.stringify(input),
  })
}

function listCRSProfiles(accessToken: string, signal?: AbortSignal): Promise<{ items: CRSProfilePack[] }> {
  return request(accessToken, '/v1/security-policies/crs-profiles', { signal })
}

function getSiteCRS(accessToken: string, siteID: string, signal?: AbortSignal): Promise<SiteCRSState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/crs`, { signal })
}

function setSiteCRS(
  accessToken: string, siteID: string, siteVersion: number, input: SiteCRSOverride, idempotencyKey: string,
): Promise<SiteCRSState> {
  return request(accessToken, `/v1/sites/${encodeURIComponent(siteID)}/crs`, {
    method: 'PUT', headers: writeHeaders(idempotencyKey, siteVersion), body: JSON.stringify(input),
  })
}

function ipIntelStatus(accessToken: string, signal?: AbortSignal): Promise<IPIntelStatus> {
  return request(accessToken, '/v1/security-policies/ip-intel-status', { signal })
}

function evaluate(
  accessToken: string, id: string, version: number, facts: RequestFacts,
): Promise<SecurityPolicyEvaluation> {
  return request(accessToken, `/v1/security-policies/${encodeURIComponent(id)}/evaluate`, {
    method: 'POST', headers: { 'If-Match': `"${version}"` }, body: JSON.stringify(facts),
  })
}

function activationWriteHeaders(metadata: SecurityActivationWriteMetadata): HeadersInit {
  return {
    'Idempotency-Key': metadata.idempotencyKey,
    'X-Request-ID': metadata.requestId,
    Traceparent: metadata.traceparent,
    ...(metadata.correlationId ? { 'X-Correlation-ID': metadata.correlationId } : {}),
    ...(metadata.taskId ? { 'X-Task-ID': metadata.taskId } : {}),
  }
}

function getActivationStatus(
  accessToken: string,
  siteID: string,
  policyKind: SecurityPolicyKind,
  signal?: AbortSignal,
): Promise<SecurityActivationStatus> {
  const values = new URLSearchParams({ site_id: siteID, policy_kind: policyKind })
  return request(accessToken, `/v1/site-publications/security-activations?${values}`, { signal })
}

/** waf-rebind: bound sites still behind their WAF/CC library (the control
 * plane republishes them itself) and those the package does not entitle. */
export interface SecurityPolicyRebindStatus {
  pending_sites: number
  package_denied_sites: number
}

function getRebindStatus(
  accessToken: string,
  policyKind: 'waf' | 'cc',
  signal?: AbortSignal,
): Promise<SecurityPolicyRebindStatus> {
  const values = new URLSearchParams({ policy_kind: policyKind })
  return request(accessToken, `/v1/site-publications/security-activations/rebind-status?${values}`, { signal })
}

function publishActivation(
  accessToken: string,
  input: SecurityActivationPublishInput,
  metadata: SecurityActivationWriteMetadata,
): Promise<SecurityActivationStartResult> {
  return request(accessToken, '/v1/site-publications/security-activations', {
    method: 'POST', headers: activationWriteHeaders(metadata), body: JSON.stringify(input),
  })
}

function reconcileActivation(
  accessToken: string,
  candidateID: string,
  input: { promotion_cas: SecurityActivationPromotionCAS },
  metadata: SecurityActivationWriteMetadata,
): Promise<SecurityActivationReconcileResult> {
  return request(accessToken, `/v1/site-publications/security-activations/${encodeURIComponent(candidateID)}/reconcile`, {
    method: 'POST', headers: activationWriteHeaders(metadata), body: JSON.stringify(input),
  })
}

function rollbackActivation(
  accessToken: string,
  candidateID: string,
  input: SecurityActivationRollbackInput,
  metadata: SecurityActivationWriteMetadata,
): Promise<SecurityActivationStartResult> {
  return request(accessToken, `/v1/site-publications/security-activations/${encodeURIComponent(candidateID)}/rollback`, {
    method: 'POST', headers: activationWriteHeaders(metadata), body: JSON.stringify(input),
  })
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  if (!globalThis.crypto?.getRandomValues) throw new ApiError('Secure request metadata unavailable', 0, 'request_metadata_unavailable')
  globalThis.crypto.getRandomValues(bytes)
  if (bytes.every((byte) => byte === 0)) bytes[0] = 1
  return bytes
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function randomUUID(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID().toLowerCase()
  const bytes = randomBytes(16)
  bytes[6] = (bytes[6]! & 0x0f) | 0x40
  bytes[8] = (bytes[8]! & 0x3f) | 0x80
  const value = hex(bytes)
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`
}

export function newSecurityActivationWriteMetadata(
  operation: 'publish' | 'reconcile' | 'rollback',
): SecurityActivationWriteMetadata {
  const requestId = randomUUID()
  return {
    requestId,
    idempotencyKey: `security-activation-${operation}-${requestId}`,
    traceparent: `00-${hex(randomBytes(16))}-${hex(randomBytes(8))}-01`,
  }
}

export const securityPoliciesApi = {
  batch,
  catalogRules,
  create,
  createReference,
  evaluate,
  getActivationStatus,
  getRebindStatus,
  getSiteCRS,
  getSiteQuickBlock,
  ipIntelStatus,
  list,
  listCRSProfiles,
  listReferences,
  publishActivation,
  reconcileActivation,
  remove,
  removeReference,
  rollbackActivation,
  setQuickBlock,
  setSiteCRS,
  setSiteQuickBlock,
  update,
  updateReference,
  setReferenceEnabled,
}
