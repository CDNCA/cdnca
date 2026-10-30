import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Dropdown,
  Empty,
  Input,
  InputNumber,
  Popconfirm,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronUp,
  History,
  Plus,
  RefreshCw,
  Trash2,
} from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import '../../i18n/siteEditV4'
import { SiteTabSummary } from './SiteTabSummary'

import { ApiError } from '../../api/auth'
import { writeOutcomeUnknown as unknownOutcome } from './writeOutcome'
import {
  cacheConditionalRulesMax,
  cacheMaxObjectBytesLimit,
  cachePathRegexMaxLength,
  cachePoliciesApi,
  cachePolicySchemaV2,
  normalizeContentTypes,
  ruleExtraFields,
  validExactPath,
  validRuleExtras,
  validContentTypes,
  validExtensions,
  type CachePolicyDocument,
  type CachePolicyHistoryParams,
  type CachePolicyMode,
  type CachePolicyRule,
  type CachePolicyView,
  type CacheQueryMode,
  type CacheRuleAction,
  type PublishCachePolicyInput,
} from '../../api/cachePolicies'
import {
  cacheOperationsApi,
  type CacheOperation,
  type CacheOperationScope,
  type CreateCacheOperationInput,
} from '../../api/cacheOperations'
import {
  cacheWriteIdentity,
  cacheWriteOwner,
  pendingCacheWriteKey,
  rememberCacheWrite,
  sendCacheWrite,
  settleCacheWrite,
} from '../cacheWriteJournal'
import type { ScopeKind } from '../../api/auth'
import { useSessionStore } from '../../auth/session'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/cacheOperations'
import '../../i18n/cachePolicy'
import { formatDateTime } from '../../i18n/formatters'
import './CacheSiteTab.css'
import CacheRuleDialog from './CacheRuleDialog'
import { ruleScope, ruleSliceBytes } from './cacheRuleScope'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import SiteEditState from './SiteEditState'
import { useCommitRequest, useInstantFeedback } from './instantSave'

const minQuota = 64 * 1024 * 1024
const maxQuota = 16 * 1024 ** 4
const maxTTL = 365 * 24 * 60 * 60
const extensionPattern = /^\.[a-z0-9][a-z0-9_+-]{0,15}$/
const queryNamePattern = /^[A-Za-z0-9][A-Za-z0-9_.~-]{0,127}$/
const headerPattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/
const forbiddenVaryHeaders = new Set(['authorization', 'cookie', 'proxy-authorization', 'set-cookie'])

interface CacheSiteTabProps {
  siteId: string
  accessToken: string
  scopeKind: ScopeKind
  permissions: string[]
  lockedForTenant: boolean
  sessionEpoch: number
  userId: string
  scopeId: string
  tenantId: string | null
  /** The site's tenant scope: a platform administrator reads and writes the
   * site's cache policy there (/v1/admin/cache-policies, site-parity3b). */
  siteScopeId?: string
  onDirtyChange: (state: { dirty: boolean; uncertain: boolean; pending: boolean }) => void
  // tp-b3c: site-level switches shown in 其他设置 below the rules (X-CDN-Cache)
  extra?: ReactNode
}

// 快速设置缓存 (competitor presets, values as its PUT bodies): 首页
// full_path "/" 1d; 全站 dir "/" 3d; 静态 suffix 7d ignore_arg; 视频 suffix
// 30d range; Wordpress dir "/" 3d + no_cache $http_cookie ~ wordpress_logged_in
// (and wp-admin / wp-login, which must never be cached either).
const day = 24 * 60 * 60
const quickPresets: Record<string, Omit<CachePolicyRule, 'order'>> = {
  home: { extensions: [], path_prefix: '', path_exact: '/', status_codes: [], action: 'cache', ttl_seconds: day, browser_ttl_seconds: 0 },
  site: { extensions: [], path_prefix: '/', status_codes: [], action: 'cache', ttl_seconds: 3 * day, browser_ttl_seconds: 0 },
  static: { extensions: ['.jpg', '.jpeg', '.png', '.gif', '.ico', '.css', '.js', '.svg', '.bmp', '.webp', '.woff', '.woff2'], path_prefix: '', status_codes: [], action: 'cache', ttl_seconds: 7 * day, browser_ttl_seconds: 0, ignore_query: true },
  video: { extensions: ['.mp4', '.avi', '.mov', '.webm', '.m3u8', '.ts'], path_prefix: '', status_codes: [], action: 'cache', ttl_seconds: 30 * day, browser_ttl_seconds: 0, slice_bytes: ruleSliceBytes },
  wordpress: {
    extensions: [], path_prefix: '/', status_codes: [], action: 'cache', ttl_seconds: 3 * day, browser_ttl_seconds: 0,
    no_cache: [
      { source: 'header', name: 'cookie', pattern: 'wordpress_logged_in|wp-postpass|comment_author' },
      { source: 'path', pattern: '^/wp-(?:admin|login\\.php)' },
    ],
  },
}

const newRule: CachePolicyRule = {
  order: 0, extensions: [], path_prefix: '/', status_codes: [], action: 'cache', ttl_seconds: day, browser_ttl_seconds: 0,
}

interface RuleDialogState {
  // null = a new rule
  index: number | null
  rule: CachePolicyRule
  // CU-SITE-03: why the save carrying this rule was refused
  error?: string
}

interface WriteAttempt {
  input: PublishCachePolicyInput
  base: CachePolicyDocument
  idempotencyKey: string
  serializedBody: string
}

interface ConflictState {
  base: CachePolicyDocument
  draft: CachePolicyDocument
  latest: CachePolicyView | null
}

function cloneDocument(document: CachePolicyDocument): CachePolicyDocument {
  return {
    ...(document.schema_version === cachePolicySchemaV2 ? { schema_version: cachePolicySchemaV2 } : {}),
    mode: document.mode,
    rules: document.rules.map((rule) => ({
      order: rule.order,
      extensions: [...(rule.extensions ?? [])],
      path_prefix: rule.path_prefix ?? '',
      status_codes: [...(rule.status_codes ?? [])],
      ...(rule.action === undefined ? {} : { action: rule.action }),
      ttl_seconds: rule.ttl_seconds,
      ...(rule.browser_ttl_seconds === undefined ? {} : { browser_ttl_seconds: rule.browser_ttl_seconds }),
      ...conditionFields(rule),
      ...ruleExtraFields(rule),
    })),
    query_mode: document.query_mode,
    query_names: [...document.query_names],
    vary_headers: [...document.vary_headers],
    disk_quota_bytes: document.disk_quota_bytes,
    ...extensionFields(document),
  }
}

// conditionFields keeps a rule's path regex and content types only when set
// (the wire omits them otherwise).
function conditionFields(rule: CachePolicyRule): Partial<CachePolicyRule> {
  return {
    ...(rule.path_regex ? { path_regex: rule.path_regex } : {}),
    ...(rule.content_types?.length ? { content_types: [...rule.content_types] } : {}),
  }
}

// extensionFields keeps only the extensions that are on (the wire omits
// the others, so documents compare equal however they were built).
function extensionFields(document: CachePolicyDocument): Partial<CachePolicyDocument> {
  if (document.mode === 'disabled') return {}
  return {
    ...(document.stale_if_error ? { stale_if_error: true } : {}),
    ...(document.stale_if_error && document.background_update ? { background_update: true } : {}),
    ...(document.min_object_bytes ? { min_object_bytes: document.min_object_bytes } : {}),
    ...(document.max_object_bytes ? { max_object_bytes: document.max_object_bytes } : {}),
    ...(document.slice_bytes ? { slice_bytes: document.slice_bytes } : {}),
  }
}

function emptyDocument(): CachePolicyDocument {
  return {
    mode: 'disabled',
    rules: [],
    query_mode: 'preserve',
    query_names: [],
    vary_headers: [],
    disk_quota_bytes: 0,
  }
}

// usesSchemaV2: a v2 document stays v2 (the server refuses an explicit
// schema_version other than 2, validate.go:360-363); a v1 draft becomes v2
// once a rule needs a v2 field (no_cache, a browser TTL or a per-rule
// setting).
function usesSchemaV2(document: CachePolicyDocument): boolean {
  return document.schema_version === cachePolicySchemaV2 ||
    document.rules.some((rule) => rule.action === 'no_cache' || (rule.browser_ttl_seconds ?? 0) !== 0 ||
      Object.keys(ruleExtraFields(rule)).length > 0)
}

function ruleAction(rule: CachePolicyRule): CacheRuleAction {
  return rule.action ?? 'cache'
}

function sameDocument(left: CachePolicyDocument, right: CachePolicyDocument): boolean {
  return JSON.stringify(normalizeDocument(left)) === JSON.stringify(normalizeDocument(right))
}

function writeKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `cache-policy-${Date.now()}-${Math.random()}`
}

function localError(error: unknown, t: TFunction<'cachePolicy'>): string {
  if (!(error instanceof ApiError)) return t('errors.network_error')
  const known = new Set([
    'network_error', 'invalid_response', 'permission_denied', 'revision_conflict',
    'idempotency_conflict', 'validation_error', 'invalid_request', 'not_found',
    'service_unavailable', 'request_failed',
  ])
  return known.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.request_failed'))
}

// One 清空全部缓存 request and the journal entry it keeps
// while its outcome is unknown.
interface FlushAttempt {
  scope: CacheOperationScope
  input: CreateCacheOperationInput
  owner: string
  identity: string
  key: string
  /** An earlier attempt with this key has an unknown outcome: read its receipt first. */
  recorded: boolean
}

const flushSessionChanged = new ApiError('Session changed', 401, 'authentication_required')

// As on the cache operations page: daily_limit_exceeded is a 429 the server
// answers after refusing the write, a definite outcome.
function flushOutcomeUnknown(error: unknown): boolean {
  if (error === flushSessionChanged) return false
  if (error instanceof ApiError && error.code === 'daily_limit_exceeded') return false
  return unknownOutcome(error)
}

// A refusal of the flush (also one read from its receipt) carries a cache
// operation code; it is shown with the cache operations page's wording.
function flushError(error: unknown, t: TFunction<'cacheOperations'>): string {
  if (!(error instanceof ApiError)) return t('errors.request_failed')
  const known = new Set([
    'authentication_required', 'invalid_request', 'validation_error', 'permission_denied', 'not_found',
    'idempotency_conflict', 'entitlement_denied', 'daily_limit_exceeded', 'no_carrying_node',
    'target_node_unavailable', 'wildcard_purge_unsupported', 'request_cancelled', 'service_unavailable',
    'network_error', 'invalid_response',
  ])
  const message = known.has(error.code) ? t(`errors.${error.code}`) : localizedUnknownApiError(error, t('errors.request_failed'))
  return known.has(error.code) && error.requestId ? t('errors.withRequestId', { message, requestId: error.requestId }) : message
}

// CU-SITE-03: the reason a definite refusal shows beside the rule, with the
// request ID so the user can quote it.
function ruleSaveError(error: ApiError, t: TFunction<'cachePolicy'>): string {
  const reason = localError(error, t)
  return error.requestId ? `${reason} ${t('history.requestId')}: ${error.requestId}` : reason
}

function commaValues(value: string): string[] {
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

// User 10-27: "Vary 请求头是啥意思", "磁盘配额 这是啥单位". Common headers are
// picked from a list (others can still be typed); sizes are entered in a unit.
const commonVaryHeaders = ['accept-encoding', 'accept-language', 'user-agent', 'accept', 'origin', 'sec-ch-ua-mobile'] as const
const sizeUnits = [{ key: 'kb', bytes: 1024 }, { key: 'mb', bytes: 1024 ** 2 }, { key: 'gb', bytes: 1024 ** 3 }, { key: 'tb', bytes: 1024 ** 4 }] as const
type SizeUnit = (typeof sizeUnits)[number]['key']

// The largest unit the value is a whole multiple of (0 shows in MB).
function sizeUnitOf(bytes: number, units: readonly SizeUnit[]): SizeUnit {
  const fitting = sizeUnits.filter((unit) => units.includes(unit.key) && bytes > 0 && bytes % unit.bytes === 0)
  return fitting.at(-1)?.key ?? (units.includes('mb') ? 'mb' : units[0])
}

/** A byte count entered as a number and a unit; the value stays in bytes. */
// Out-of-range values below the minimum are left to the form validation.
function ByteSizeInput({ label, value, units, max, disabled, onChange }: {
  label: string; value: number; units: readonly SizeUnit[]; max: number; disabled: boolean; onChange: (bytes: number) => void
}) {
  const { t } = useTranslation('cachePolicy')
  // The unit follows the value (it loads after the first render) until one is picked or typed in.
  const [chosen, setChosen] = useState<SizeUnit | null>(null)
  const unit = chosen ?? sizeUnitOf(value, units)
  const factor = sizeUnits.find((item) => item.key === unit)!.bytes
  return (
    <Space.Compact>
      <InputNumber aria-label={label} min={0} max={max / factor} disabled={disabled}
        value={value / factor} onChange={(next) => { setChosen(unit); onChange(Math.min(max, Math.max(0, Math.round(Number(next ?? 0) * factor)))) }} />
      <Select aria-label={t('units.unitOf', { field: label })} value={unit} disabled={disabled} style={{ width: 80 }}
        options={units.map((key) => ({ value: key, label: t(`units.${key}`) }))} onChange={setChosen} />
    </Space.Compact>
  )
}

// The server (cachecontrol normalizeDirectoryPath) requires a leading slash
// and appends the trailing one: /api is stored as /api/.
function directoryPrefix(value: string): string {
  const prefix = value.trim()
  return prefix.startsWith('/') && !prefix.endsWith('/') ? `${prefix}/` : prefix
}

function validDirectoryPath(value: string): boolean {
  return value.startsWith('/') && value.endsWith('/') && !value.startsWith('//') &&
    !value.includes('//') && !/[?#%\\]/.test(value) &&
    !value.split('/').some((part) => part === '.' || part === '..')
}

function conditional(rule: CachePolicyRule): boolean {
  return Boolean(rule.path_regex) || (rule.content_types?.length ?? 0) > 0
}

// validPathRegex: the browser's own check (length, syntax); the server
// enforces the backtracking bounds (edgeconfig.ValidateCachePathRegex) and
// answers 400 otherwise.
function validPathRegex(value: string): boolean {
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the intent
  if (value.length > cachePathRegexMaxLength || /[\u0000-\u001f\u007f]/.test(value)) return false
  try {
    new RegExp(value)
    return true
  } catch {
    return false
  }
}

function stringSetsOverlap(left: string[], right: string[]): boolean {
  return left.length === 0 || right.length === 0 || left.some((value) => right.includes(value))
}

function pathPrefixesOverlap(left: string, right: string): boolean {
  return left === '' || right === '' || left.startsWith(right) || right.startsWith(left)
}

function intSetsOverlap(left: number[], right: number[]): boolean {
  return left.length === 0 || right.length === 0 || left.some((value) => right.includes(value))
}

// "svg" means ".svg": the server stores extensions with the dot
// (cachecontrol/validate.go extensionPattern); add it instead of refusing.
function normalizeExtension(value: string): string {
  const extension = value.trim().toLowerCase()
  return extension.startsWith('.') ? extension : `.${extension}`
}

function normalizeDocument(document: CachePolicyDocument): CachePolicyDocument {
  const mode = document.mode
  const v2 = usesSchemaV2(document)
  const rules = mode === 'override'
    ? document.rules.map((rule, index) => ({
        order: index + 1,
        extensions: [...new Set((rule.extensions ?? []).map(normalizeExtension))].sort(),
        path_prefix: directoryPrefix(rule.path_prefix ?? ''),
        status_codes: [...new Set(rule.status_codes ?? [])].sort((left, right) => left - right),
        // v2 rules always carry action and browser TTL; no_cache has both TTLs 0.
        ...(v2 ? { action: ruleAction(rule) } : {}),
        ttl_seconds: v2 && ruleAction(rule) === 'no_cache' ? 0 : rule.ttl_seconds,
        ...(v2 ? { browser_ttl_seconds: ruleAction(rule) === 'no_cache' ? 0 : rule.browser_ttl_seconds ?? 0 } : {}),
        ...conditionFields({
          ...rule,
          path_regex: (rule.path_regex ?? '').trim(),
          content_types: normalizeContentTypes(rule.content_types ?? []),
        }),
        ...ruleExtraFields(ruleAction(rule) === 'no_cache'
          ? { ...rule, ignore_query: undefined, slice_bytes: undefined, force_cache: undefined, ignore_vary: undefined, no_cache: undefined }
          : rule),
      }))
    : []
  const queryNames = document.query_mode === 'include' || document.query_mode === 'exclude'
    ? [...new Set(document.query_names.map((value) => value.trim()))].sort()
    : []
  return {
    ...(v2 ? { schema_version: cachePolicySchemaV2 } : {}),
    mode,
    rules,
    query_mode: document.query_mode,
    query_names: queryNames,
    vary_headers: [...new Set(document.vary_headers.map((value) => value.trim().toLowerCase()))].sort(),
    disk_quota_bytes: mode === 'disabled' ? 0 : document.disk_quota_bytes,
    ...extensionFields({ ...document, mode }),
  }
}

function validateDocument(document: CachePolicyDocument, t: TFunction<'cachePolicy'>): string | null {
  if (document.mode === 'override' && document.rules.length === 0) return t('validation.ruleRequired')
  if (document.mode !== 'disabled' &&
    (!Number.isInteger(document.disk_quota_bytes) || document.disk_quota_bytes < minQuota || document.disk_quota_bytes > maxQuota)) {
    return t('validation.quotaRange', { min: minQuota, max: maxQuota })
  }
  for (const rule of document.rules) {
    const noCache = ruleAction(rule) === 'no_cache'
    if (!noCache && (!Number.isInteger(rule.ttl_seconds) || rule.ttl_seconds < 1 || rule.ttl_seconds > maxTTL)) {
      return t('validation.ttlRange')
    }
    const browserTTL = rule.browser_ttl_seconds ?? 0
    if (!noCache && (!Number.isInteger(browserTTL) || browserTTL < 0 || browserTTL > rule.ttl_seconds)) {
      return t('validation.browserTtlRange')
    }
    const extensions = rule.extensions ?? []
    const statusCodes = rule.status_codes ?? []
    if (extensions.length > 32 || extensions.some((value) => !extensionPattern.test(value))) {
      return t('validation.invalidExtension')
    }
    if (rule.path_prefix && !validDirectoryPath(rule.path_prefix)) return t('validation.invalidPath')
    if (statusCodes.length > 32 || statusCodes.some((value) => !Number.isInteger(value) || value < 100 || value > 599)) {
      return t('validation.invalidStatus')
    }
    if (rule.path_regex && !validPathRegex(rule.path_regex)) return t('validation.invalidPathRegex')
    if (rule.content_types?.length && !validContentTypes(normalizeContentTypes(rule.content_types))) {
      return t('validation.invalidContentTypes')
    }
    if (rule.path_exact && !validExactPath(rule.path_exact)) return t('validation.invalidExactPath')
    if (!validRuleExtras(ruleExtraFields(rule) as Record<string, unknown>)) return t('validation.invalidCondition')
  }
  if (document.rules.filter((rule) => rule.path_regex || rule.content_types?.length).length > cacheConditionalRulesMax) {
    return t('validation.tooManyConditionalRules', { max: cacheConditionalRulesMax })
  }
  // schema v2 matches rules in order (first match wins); only v1 forbids overlap
  for (let leftIndex = 0; !usesSchemaV2(document) && leftIndex < document.rules.length; leftIndex += 1) {
    const left = document.rules[leftIndex]!
    for (let rightIndex = leftIndex + 1; rightIndex < document.rules.length; rightIndex += 1) {
      const right = document.rules[rightIndex]!
      // a rule with a path regex or content types decides per request (the
      // server exempts it from the overlap check)
      if (conditional(left) || conditional(right)) continue
      if (
        stringSetsOverlap(left.extensions ?? [], right.extensions ?? []) &&
        pathPrefixesOverlap(left.path_prefix ?? '', right.path_prefix ?? '') &&
        intSetsOverlap(left.status_codes ?? [], right.status_codes ?? [])
      ) return t('validation.overlap')
    }
  }
  const queryRequired = document.query_mode === 'include' || document.query_mode === 'exclude'
  if (queryRequired && (document.query_names.length === 0 || document.query_names.some((value) => !queryNamePattern.test(value)))) {
    return t('validation.queryNamesRequired')
  }
  if (!queryRequired && document.query_names.length > 0) return t('validation.queryNamesForbidden')
  if (document.vary_headers.length > 16 || document.vary_headers.some((value) => {
    const normalized = value.toLowerCase()
    return !headerPattern.test(value) || value === '*' || forbiddenVaryHeaders.has(normalized)
  })) return t('validation.invalidHeader')
  if (!validExtensions(document)) return t('validation.invalidExtensions')
  return null
}

function comparisonValues(values: Array<string | number>, emptyValue: string): string {
  return values.length > 0 ? values.join(', ') : emptyValue
}

function PolicyComparisonPanel({
  label,
  document,
  locale,
  t,
}: {
  label: string
  document: CachePolicyDocument
  locale?: string
  t: TFunction<'cachePolicy'>
}) {
  const normalized = normalizeDocument(document)
  const number = new Intl.NumberFormat(locale)
  const all = t('matchTypes.all')
  return (
    <section
      className="cache-policy-comparison-panel"
      aria-label={label}
      style={{ minWidth: 0, maxWidth: '100%' }}
    >
      <h4>{label}</h4>
      <dl>
        <div><dt>{t('fields.mode')}</dt><dd>{t(`modes.${normalized.mode}`)}</dd></div>
        <div>
          <dt>{t('fields.rules')}</dt>
          <dd>
            {normalized.rules.length === 0 ? '—' : (
              <ol className="cache-policy-comparison-rules">
                {normalized.rules.map((rule) => (
                  <li key={rule.order}>
                    <strong>{t('fields.order')} {number.format(rule.order)}</strong>
                    <span>{t('fields.extensions')}: {comparisonValues(rule.extensions ?? [], all)}</span>
                    <span>{t('fields.pathPrefix')}: {rule.path_prefix || all}</span>
                    <span>{t('fields.statusCodes')}: {comparisonValues(rule.status_codes ?? [], all)}</span>
                    {rule.path_regex ? <span>{t('fields.pathRegex')}: {rule.path_regex}</span> : null}
                    {rule.content_types?.length ? <span>{t('fields.contentTypes')}: {rule.content_types.join(', ')}</span> : null}
                    {rule.action ? <span>{t('fields.action')}: {t(`ruleActions.${rule.action}`)}</span> : null}
                    {rule.action !== 'no_cache' ? <span>{t('fields.ttlSeconds')}: {number.format(rule.ttl_seconds)} {t('units.seconds')}</span> : null}
                    {rule.action === 'cache' ? <span>{t('fields.browserTtlSeconds')}: {rule.browser_ttl_seconds ? `${number.format(rule.browser_ttl_seconds)} ${t('units.seconds')}` : t('help.browserTtlOff')}</span> : null}
                  </li>
                ))}
              </ol>
            )}
          </dd>
        </div>
        <div><dt>{t('fields.queryMode')}</dt><dd>{t(`queryModes.${normalized.query_mode}`)}</dd></div>
        <div><dt>{t('fields.queryNames')}</dt><dd>{comparisonValues(normalized.query_names, '—')}</dd></div>
        <div><dt>{t('fields.varyHeaders')}</dt><dd>{comparisonValues(normalized.vary_headers, '—')}</dd></div>
        <div>
          <dt>{t('fields.diskQuotaBytes')}</dt>
          <dd>{number.format(normalized.disk_quota_bytes)} {t('units.bytes')}</dd>
        </div>
      </dl>
    </section>
  )
}

function modeDocument(document: CachePolicyDocument, mode: CachePolicyMode): CachePolicyDocument {
  if (mode === 'disabled') return { ...document, mode, rules: [], disk_quota_bytes: 0 }
  if (mode === 'follow_origin') {
    return { ...document, mode, rules: [], disk_quota_bytes: document.disk_quota_bytes || minQuota }
  }
  return {
    ...document,
    mode,
    rules: document.rules.length > 0 ? document.rules : [{
      order: 1, extensions: [], path_prefix: '', status_codes: [], ttl_seconds: 3600,
    }],
    disk_quota_bytes: document.disk_quota_bytes || minQuota,
  }
}

function CacheSiteTabOwned({
  siteId,
  accessToken,
  scopeKind,
  permissions,
  lockedForTenant,
  sessionEpoch,
  userId,
  scopeId,
  tenantId,
  siteScopeId,
  onDirtyChange,
  extra,
}: CacheSiteTabProps) {
  const { t, i18n } = useTranslation('cachePolicy')
  const { t: tV4 } = useTranslation('siteEditV4')
  const { t: tOps } = useTranslation('cacheOperations')
  const queryClient = useQueryClient()
  // A platform administrator acts on the site's tenant scope (site-parity3b).
  const platformAdmin = scopeKind === 'platform' && permissions.includes('platform.admin')
  const targetScopeId = scopeKind === 'platform' ? siteScopeId : undefined
  // Appended only for an administrator, so tenant calls keep their arity.
  const scopeArg = targetScopeId ? [targetScopeId] as const : [] as const
  const canPermit = (permission: string) => permissions.includes(permission) || platformAdmin
  const tenantRead = (scopeKind === 'tenant' || Boolean(targetScopeId)) && canPermit('sites.read')
  const tenantManage = tenantRead && canPermit('sites.manage') && !lockedForTenant
  const [current, setCurrent] = useState<CachePolicyView | null>(null)
  const [draft, setDraft] = useState<CachePolicyDocument | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [validationError, setValidationError] = useState<string>()
  const [saved, setSaved] = useState(false)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const attemptRef = useRef<WriteAttempt | null>(null)
  const [conflict, setConflict] = useState<ConflictState | null>(null)
  const [compareOpen, setCompareOpen] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  // 新增/编辑缓存规则 dialog: index null = a new rule
  // CU-SITE-03: a definite refusal of the save carrying a dialog's rule
  // reopens the dialog with the typed rule and the reason (error).
  const [ruleDialog, setRuleDialog] = useState<RuleDialogState | null>(null)
  // the rule 确定 submitted, until save() sends it; then with that save's key
  const ruleDialogPendingRef = useRef<RuleDialogState | null>(null)
  const ruleDialogSentRef = useRef<{ key: string; dialog: RuleDialogState } | null>(null)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyCursor, setHistoryCursor] = useState<string>()
  const [historyStack, setHistoryStack] = useState<string[]>([])
  const [selectedHistory, setSelectedHistory] = useState<CachePolicyView | null>(null)
  const [historyDetailRevision, setHistoryDetailRevision] = useState<number>()
  const [historyDetailError, setHistoryDetailError] = useState<unknown>(null)
  const currentRef = useRef<CachePolicyView | null>(null)
  const draftRef = useRef<CachePolicyDocument | null>(null)
  const instantFeedback = useInstantFeedback()

  const currentSessionMatchesLineage = useCallback((): boolean => {
    const session = useSessionStore.getState()
    const principal = session.principal
    return session.sessionEpoch === sessionEpoch && session.accessToken === accessToken &&
      principal?.scope_kind === scopeKind && principal.user_id === userId &&
      principal.scope_id === scopeId && principal.tenant_id === tenantId
  }, [accessToken, scopeId, scopeKind, sessionEpoch, tenantId, userId])

  // 清空全部缓存 is a whole-site purge on every node carrying the site
  // (node_ids omitted); the operation is tracked on the cache operations page.
  // An attempt whose outcome is unknown keeps its key in the
  // cache write journal (shared with the cache operations page); sending it
  // again first reads the server's receipt and only resends the same request
  // with the same key when the server never received it.
  const flushAttempt = (): FlushAttempt => {
    const scope: CacheOperationScope = targetScopeId ? { kind: 'admin', scopeId: targetScopeId } : { kind: 'tenant' }
    const input: CreateCacheOperationInput = {
      site_id: siteId, action: 'purge', target_type: 'whole_site', targets: [], node_ids: [], max_retries: 3,
    }
    const owner = cacheWriteOwner(scopeId, userId, JSON.stringify(scope))
    const identity = cacheWriteIdentity('create', input)
    const recorded = pendingCacheWriteKey(owner, identity)
    return { scope, input, owner, identity, key: recorded ?? `cache-flush-${writeKey()}`, recorded: recorded !== undefined }
  }
  const flushMutation = useMutation<CacheOperation, Error, FlushAttempt>({
    mutationFn: async (attempt) => {
      if (!currentSessionMatchesLineage()) throw flushSessionChanged
      return sendCacheWrite(() => accessToken, attempt.scope, { action: 'create', key: attempt.key }, attempt.recorded,
        () => cacheOperationsApi.create(accessToken, attempt.scope, attempt.input, attempt.key), flushOutcomeUnknown)
    },
    onSuccess: (_result, attempt) => settleCacheWrite(attempt.owner, attempt.identity, attempt.key),
    onError: (error, attempt) => {
      if (error === flushSessionChanged) return
      if (flushOutcomeUnknown(error)) rememberCacheWrite(attempt.owner, attempt.identity, attempt.key)
      else settleCacheWrite(attempt.owner, attempt.identity, attempt.key)
    },
  })
  const flushUncertain = flushMutation.isError && flushOutcomeUnknown(flushMutation.error)

  const currentQueryKey = [
    'cache-policy', sessionEpoch, userId, scopeKind, scopeId, tenantId, siteId, targetScopeId,
  ] as const

  const query = useQuery({
    queryKey: currentQueryKey,
    queryFn: async () => {
      try {
        const result = await cachePoliciesApi.get(accessToken, siteId, ...scopeArg)
        if (!currentSessionMatchesLineage()) throw new ApiError('permission denied', 403, 'permission_denied')
        return result
      } catch (error) {
        if (error instanceof ApiError && error.status === 404 && currentSessionMatchesLineage()) return null
        throw error
      }
    },
    enabled: Boolean(accessToken && siteId && tenantRead),
  })

  useEffect(() => {
    if (query.data === undefined || conflict || attemptRef.current || !currentSessionMatchesLineage()) return
    if (draftRef.current && !sameDocument(currentRef.current?.document ?? emptyDocument(), draftRef.current)) return
    currentRef.current = query.data
    draftRef.current = cloneDocument(query.data?.document ?? emptyDocument())
    setCurrent(query.data)
    setDraft(draftRef.current)
  }, [conflict, currentSessionMatchesLineage, query.data])

  const historyParams: CachePolicyHistoryParams = historyCursor
    ? { limit: 20, cursor: historyCursor }
    : { limit: 20 }
  const historyQuery = useQuery({
    queryKey: [
      'cache-policy-history', sessionEpoch, userId, scopeKind, scopeId, tenantId, siteId, targetScopeId,
      historyCursor,
    ],
    queryFn: async () => {
      const result = await cachePoliciesApi.history(accessToken, siteId, historyParams, ...scopeArg)
      if (!currentSessionMatchesLineage()) throw new ApiError('permission denied', 403, 'permission_denied')
      return result
    },
    enabled: Boolean(accessToken && siteId && tenantRead && historyOpen),
  })

  function currentSessionCanManage(): boolean {
    const session = useSessionStore.getState()
    const live = session.principal?.permissions ?? []
    const livePermit = (permission: string) => live.includes(permission) ||
      (session.principal?.scope_kind === 'platform' && live.includes('platform.admin'))
    return tenantManage && currentSessionMatchesLineage() && session.principal?.scope_kind === scopeKind &&
      livePermit('sites.read') && livePermit('sites.manage')
  }

  const mutation = useMutation<CachePolicyView, Error, WriteAttempt>({
    mutationFn: (next) => {
      if (!currentSessionCanManage()) throw new ApiError('permission denied', 403, 'permission_denied')
      return cachePoliciesApi.publish(
        accessToken,
        siteId,
        next.input,
        next.idempotencyKey,
        next.serializedBody,
        ...scopeArg,
      )
    },
    onSuccess: (result, completed) => {
      if (!currentSessionMatchesLineage() || attemptRef.current?.idempotencyKey !== completed.idempotencyKey) return
      attemptRef.current = null
      setAttempt(null)
      // An edit made while the save ran stays (and is saved next).
      const editedSince = draftRef.current !== null && !sameDocument(draftRef.current, completed.input.document)
      currentRef.current = result
      if (!editedSince) draftRef.current = cloneDocument(result.document)
      setCurrent(result)
      setDraft(draftRef.current)
      setWriteError(null)
      setValidationError(undefined)
      setConflict(null)
      setCompareOpen(false)
      setSaved(true)
      settleRuleDialog(completed.idempotencyKey)
      instantFeedback.success()
      queryClient.setQueryData(currentQueryKey, result)
      void queryClient.invalidateQueries({
        queryKey: ['cache-policy-history', sessionEpoch, userId, scopeKind, scopeId, tenantId, siteId],
      })
    },
    onError: (error, failed) => {
      if (!currentSessionMatchesLineage() || attemptRef.current?.idempotencyKey !== failed.idempotencyKey) return
      const apiError = error instanceof ApiError ? error : new ApiError('network error', 0, 'network_error')
      if (apiError.code === 'revision_conflict' || apiError.status === 412) {
        attemptRef.current = null
        setAttempt(null)
        setWriteError(null)
        setConflict({ base: cloneDocument(failed.base), draft: cloneDocument(failed.input.document), latest: null })
        settleRuleDialog(failed.idempotencyKey)
        void loadConflictLatest()
        return
      }
      setWriteError(apiError)
      if (unknownOutcome(apiError)) {
        setAttempt(failed)
        // the exact request stays frozen for 重试 on the page
        settleRuleDialog(failed.idempotencyKey)
      } else {
        settleRuleDialog(failed.idempotencyKey, ruleSaveError(apiError, t))
        attemptRef.current = null
        setAttempt(null)
        // A refused change goes back to the saved policy.
        draftRef.current = cloneDocument(currentRef.current?.document ?? emptyDocument())
        setDraft(draftRef.current)
      }
    },
  })

  const uncertain = Boolean(attempt && writeError && unknownOutcome(writeError))
  const writesLocked = mutation.isPending || uncertain
  // Controls stay editable during a save (the next save waits); an unknown outcome locks them for the exact retry.
  const editLocked = uncertain
  const originalDocument = current?.document ?? emptyDocument()
  const dirty = Boolean(draft && !sameDocument(originalDocument, draft))

  useEffect(() => {
    onDirtyChange({ dirty, uncertain, pending: mutation.isPending })
    return () => onDirtyChange({ dirty: false, uncertain: false, pending: false })
  }, [dirty, mutation.isPending, onDirtyChange, uncertain])

  // A change saves at once (typed fields on blur / Enter); a running save sends the latest draft after it.
  function updateDraft(next: CachePolicyDocument) {
    if (!tenantManage || uncertain || conflict) return
    draftRef.current = next
    setDraft(next)
    setWriteError(null)
    setValidationError(undefined)
    setSaved(false)
    commits.requestUnlessTyping()
  }

  function begin(input: PublishCachePolicyInput, base = originalDocument, dialog: RuleDialogState | null = null) {
    if (!currentSessionCanManage() || writesLocked) return
    const serializedBody = JSON.stringify(input)
    const next = { input, base: cloneDocument(base), idempotencyKey: writeKey(), serializedBody }
    ruleDialogSentRef.current = dialog ? { key: next.idempotencyKey, dialog } : null
    attemptRef.current = next
    setAttempt(next)
    setWriteError(null)
    setSaved(false)
    mutation.mutate(next)
  }

  function save() {
    const dialog = ruleDialogPendingRef.current
    ruleDialogPendingRef.current = null
    if (!draft || !dirty || !tenantManage || writesLocked || conflict) return
    const normalized = normalizeDocument(draft)
    const error = validateDocument(normalized, t)
    if (error) {
      // the rule stays in the draft; the reason shows on the page
      setValidationError(error)
      return
    }
    setDraft(normalized)
    begin({ expected_revision: current?.revision ?? 0, document: normalized }, originalDocument, dialog)
  }

  // A definite refusal (error) of the save carrying a dialog's rule reopens
  // that dialog with the typed rule; any other outcome just forgets it.
  function settleRuleDialog(idempotencyKey: string, error?: string) {
    const sent = ruleDialogSentRef.current
    if (sent?.key !== idempotencyKey) return
    ruleDialogSentRef.current = null
    if (error) setRuleDialog({ ...sent.dialog, error })
  }

  const commits = useCommitRequest(save, mutation.isPending || query.isFetching)

  function retrySameRequest() {
    if (!attempt || !currentSessionCanManage() || mutation.isPending) return
    setWriteError(null)
    mutation.mutate(attempt)
  }

  function retryAfterReload() {
    if (!conflict?.latest || !currentSessionCanManage()) return
    if (!window.confirm(t('confirm.overwriteLatest'))) return
    const normalized = normalizeDocument(conflict.draft)
    const error = validateDocument(normalized, t)
    if (error) {
      setValidationError(error)
      return
    }
    currentRef.current = conflict.latest
    draftRef.current = normalized
    setCurrent(conflict.latest)
    setDraft(normalized)
    setConflict(null)
    setCompareOpen(false)
    begin({ expected_revision: conflict.latest.revision, document: normalized }, conflict.latest.document)
  }

  function loadLatest() {
    if (!conflict?.latest) return
    currentRef.current = conflict.latest
    draftRef.current = cloneDocument(conflict.latest.document)
    setCurrent(conflict.latest)
    setDraft(draftRef.current)
    setConflict(null)
    setCompareOpen(false)
    setValidationError(undefined)
    setWriteError(null)
    setSaved(false)
    queryClient.setQueryData(currentQueryKey, conflict.latest)
  }

  async function loadConflictLatest() {
    setWriteError(null)
    try {
      const latest = await cachePoliciesApi.get(accessToken, siteId, ...scopeArg)
      if (!currentSessionMatchesLineage()) return
      setConflict((value) => value ? { ...value, latest } : value)
    } catch (error) {
      if (currentSessionMatchesLineage()) setWriteError(error)
    }
  }

  async function loadHistoryRevision(revision: number) {
    setHistoryDetailRevision(revision)
    setHistoryDetailError(null)
    try {
      const result = await cachePoliciesApi.getRevision(accessToken, siteId, revision, ...scopeArg)
      if (!currentSessionMatchesLineage()) return
      setSelectedHistory(result)
    } catch (error) {
      if (currentSessionMatchesLineage()) setHistoryDetailError(error)
    }
  }

  function updateRule(index: number, next: CachePolicyRule) {
    if (!draft) return
    updateDraft({
      ...draft,
      rules: draft.rules.map((rule, ruleIndex) => ruleIndex === index ? next : rule),
    })
  }

  // addRule appends a rule; with no rules yet it switches to 自定义规则 first
  function addRule(rule: Omit<CachePolicyRule, 'order'>) {
    if (!draft) return
    const base = draft.mode === 'override' ? draft : { ...draft, mode: 'override' as const, rules: [], disk_quota_bytes: draft.disk_quota_bytes || minQuota }
    if (base.rules.length >= 100) return
    updateDraft({ ...base, rules: [...base.rules, { ...rule, order: base.rules.length + 1 }] })
  }

  function moveRule(index: number, direction: -1 | 1) {
    if (!draft) return
    const target = index + direction
    if (target < 0 || target >= draft.rules.length) return
    const rules = [...draft.rules]
    ;[rules[index], rules[target]] = [rules[target], rules[index]]
    updateDraft({ ...draft, rules: rules.map((rule, ruleIndex) => ({ ...rule, order: ruleIndex + 1 })) })
  }

  async function refreshPolicy() {
    if (dirty && !window.confirm(t('confirm.refreshDiscard'))) return
    const result = await query.refetch()
    if (result.data === undefined || !currentSessionMatchesLineage()) return
    currentRef.current = result.data
    draftRef.current = cloneDocument(result.data?.document ?? emptyDocument())
    setCurrent(result.data)
    setDraft(draftRef.current)
    setConflict(null)
    setCompareOpen(false)
    setValidationError(undefined)
    setWriteError(null)
    setSaved(false)
  }

  const historyColumns: TableColumnsType<CachePolicyView> = [
    {
      title: t('history.revision'),
      dataIndex: 'revision',
      className: 'cache-policy-history-col-revision',
    },
    {
      title: t('history.createdAt'),
      dataIndex: 'created_at',
      className: 'cache-policy-history-col-created-at',
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value,
    },
    {
      title: t('history.createdBy'),
      dataIndex: 'created_by_user_id',
      className: 'cache-policy-history-col-created-by',
    },
    {
      title: t('history.requestId'),
      dataIndex: 'request_id',
      className: 'cache-policy-history-col-request-id',
    },
    {
      title: t('history.view'),
      key: 'view',
      className: 'cache-policy-history-col-action',
      render: (_: unknown, item) => (
        <Button
          type="link"
          size="small"
          onClick={() => void loadHistoryRevision(item.revision)}
        >
          {t('history.view')}
        </Button>
      ),
    },
  ]

  function ruleScopeText(rule: CachePolicyRule): string {
    const scope = ruleScope(rule)
    const label = t(`dialog.scopes.${scope}`)
    if (scope === 'dir') return `${label} ${rule.path_prefix}`
    if (scope === 'path') return `${label} ${rule.path_exact}`
    if (scope === 'suffix') return `${label} ${(rule.extensions ?? []).map((value) => value.replace(/^\./, '')).join('|')}`
    return label
  }

  function ttlText(seconds: number): string {
    if (seconds % 86400 === 0) return `${seconds / 86400}${t('dialog.units.d')}`
    if (seconds % 3600 === 0) return `${seconds / 3600}${t('dialog.units.h')}`
    return `${seconds}${t('dialog.units.s')}`
  }

  function ruleFlags(rule: CachePolicyRule): string {
    if (ruleAction(rule) === 'no_cache') return t('table.noCacheRule')
    const flags: string[] = []
    if (rule.ignore_query) flags.push(t('table.flags.ignoreQuery'))
    if (rule.force_cache === false) flags.push(t('table.flags.noForce'))
    else flags.push(t('table.flags.forceCache'))
    if ((rule.slice_bytes ?? draft?.slice_bytes ?? 0) > 0) flags.push(t('table.flags.slice'))
    if (rule.ignore_vary) flags.push(t('table.flags.ignoreVary'))
    if (rule.no_cache?.length) flags.push(t('table.flags.noCache', { count: rule.no_cache.length }))
    return flags.join(' · ')
  }

  const ruleColumns: TableColumnsType<CachePolicyRule> = [
    { title: t('fields.order'), key: 'order', width: 64, render: (_: unknown, __: CachePolicyRule, index) => index + 1 },
    { title: t('table.scope'), key: 'scope', render: (_: unknown, rule) => ruleScopeText(rule) },
    { title: t('table.expire'), key: 'expire', width: 110,
      render: (_: unknown, rule) => ruleAction(rule) === 'no_cache' ? t('table.none') : ttlText(rule.ttl_seconds) },
    { title: t('table.options'), key: 'options', render: (_: unknown, rule) => ruleFlags(rule) },
    {
      title: t('table.actions'), key: 'actions', width: 168,
      render: (_: unknown, rule, index) => (
        <Space size={2}>
          <Button type="link" size="small" disabled={!tenantManage || editLocked}
            onClick={() => setRuleDialog({ index, rule })}>{t('table.edit')}</Button>
          <Tooltip title={t('actions.moveUp')}><Button type="text" size="small" aria-label={t('actions.moveUp')} icon={<ArrowUp size={14} aria-hidden="true" />} disabled={!tenantManage || editLocked || index === 0} onClick={() => moveRule(index, -1)} /></Tooltip>
          <Tooltip title={t('actions.moveDown')}><Button type="text" size="small" aria-label={t('actions.moveDown')} icon={<ArrowDown size={14} aria-hidden="true" />} disabled={!tenantManage || editLocked || index === (draft?.rules.length ?? 0) - 1} onClick={() => moveRule(index, 1)} /></Tooltip>
          <Tooltip title={t('actions.removeRule')}><Button danger type="text" size="small" aria-label={t('actions.removeRule')} icon={<Trash2 size={14} aria-hidden="true" />} disabled={!tenantManage || editLocked} onClick={() => draft && updateDraft({ ...draft, rules: draft.rules.filter((_, ruleIndex) => ruleIndex !== index).map((item, ruleIndex) => ({ ...item, order: ruleIndex + 1 })) })} /></Tooltip>
        </Space>
      ),
    },
  ]

  function submitRule(rule: CachePolicyRule) {
    const dialog = ruleDialog
    setRuleDialog(null)
    if (!dialog) return
    // CU-SITE-03: kept until the save carrying the rule settles
    ruleDialogPendingRef.current = { index: dialog.index, rule }
    if (dialog.index === null) addRule(rule)
    else updateRule(dialog.index, { ...rule, order: dialog.index + 1 })
    // 确定 is the commit, wherever the focus is left
    commits.request()
  }

  if (!tenantRead) {
    return (
      <section className="cache-policy-tab" data-testid="cache-policy-tab" style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}>
        <SiteEditState status="forbidden" title={t('states.forbiddenTitle')} detail={t('states.forbiddenDescription')} />
      </section>
    )
  }

  if (query.isPending) {
    return (
      <section className="cache-policy-tab" data-testid="cache-policy-tab" aria-busy="true" style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}>
        <SiteEditState status="loading" label={t('states.loading')} />
      </section>
    )
  }

  if (query.isError) {
    const forbidden = query.error instanceof ApiError && query.error.status === 403
    return (
      <section className="cache-policy-tab" data-testid="cache-policy-tab" style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}>
        {forbidden ? (
          <SiteEditState status="forbidden" title={t('states.forbiddenTitle')} detail={localError(query.error, t)} />
        ) : (
          <FeedbackWhen title={t('states.loadError')} detail={localError(query.error, t)} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
        )}
      </section>
    )
  }

  if (!draft) {
    return (
      <section className="cache-policy-tab" data-testid="cache-policy-tab" aria-busy="true" style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}>
        <SiteEditState status="loading" label={t('states.loading')} />
      </section>
    )
  }

  return (
    <section
      className="cache-policy-tab"
      data-testid="cache-policy-tab"
      aria-labelledby="cache-policy-title"
      aria-busy={query.isFetching || mutation.isPending}
      style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}
      {...commits.typingProps}
    >
      <SiteTabSummary items={[
        { key: 'mode', label: t('fields.mode'), value: t(`modes.${draft.mode}`), target: 'cache-policy-other-title',
          tone: draft.mode === 'disabled' ? 'off' : 'plain' },
        { key: 'rules', label: t('title'), target: 'cache-policy-title',
          value: tV4('summary.count', { count: draft.mode === 'override' ? draft.rules.length : 0 }) },
        { key: 'query', label: t('fields.queryMode'), value: t(`queryModes.${draft.query_mode}`), target: 'cache-policy-other-title' },
        ...(conflict ? [{ key: 'dirty', label: t('actions.save'), value: tV4('summary.cache.unsaved'), tone: 'warn' as const }] : []),
      ]} />
      <header className="cache-policy-heading">
        <div className="cache-policy-title-line">
          <h2 id="cache-policy-title">{t('title')}</h2>
          <span>{t('count', { count: draft.mode === 'override' ? draft.rules.length : 0 })}</span>
        </div>
        <Space wrap>
          <Button
            type="primary"
            icon={<Plus size={14} aria-hidden="true" />}
            disabled={!tenantManage || editLocked || draft.rules.length >= 100}
            onClick={() => setRuleDialog({ index: null, rule: newRule })}
          >
            {t('actions.addRule')}
          </Button>
          <Dropdown
            disabled={!tenantManage || editLocked}
            trigger={['click']}
            menu={{
              items: Object.keys(quickPresets).map((key) => ({ key, label: t(`quick.${key}`) })),
              onClick: ({ key }) => addRule(quickPresets[key]!),
            }}
          >
            <Button disabled={!tenantManage || editLocked} icon={<ChevronDown size={14} aria-hidden="true" />} iconPosition="end">
              {t('actions.quick')}
            </Button>
          </Dropdown>
          <Tooltip title={t('actions.refresh')}>
            <Button aria-label={t('actions.refresh')} icon={<RefreshCw size={15} aria-hidden="true" />} disabled={writesLocked} onClick={() => void refreshPolicy()} />
          </Tooltip>
          <Button
            icon={<History size={15} aria-hidden="true" />}
            aria-expanded={historyOpen}
            aria-controls="cache-policy-history-panel"
            onClick={() => setHistoryOpen((value) => !value)}
          >
            {t('actions.history')}
          </Button>
        </Space>
      </header>

      {query.data === null ? <Alert type="info" showIcon message={t('states.empty')} /> : null}
      {!tenantManage ? <Alert type="info" showIcon message={t('states.readOnly')} /> : null}
      {validationError ? <Alert type="warning" showIcon message={validationError} /> : null}
      {writeError ? (
        uncertain ? (
          <OutcomeUnknown title={localError(writeError, t)} action={
            <Button size="small" disabled={!tenantManage || mutation.isPending} onClick={retrySameRequest}>{t('actions.retry')}</Button>} />
        ) : (
          <FeedbackWhen title={localError(writeError, t)} action={conflict && !conflict.latest ? (
            <Button size="small" onClick={() => void loadConflictLatest()}>{t('actions.retry')}</Button>
          ) : undefined} />
        )
      ) : null}
      {conflict ? (
        <Alert
          type="warning"
          showIcon
          message={t('states.conflictTitle')}
          description={t('states.conflictDescription')}
          action={(
            <Space wrap>
              <Button size="small" disabled={!conflict.latest} onClick={() => setCompareOpen((value) => !value)}>{t('actions.compare')}</Button>
              <Button size="small" disabled={!conflict.latest} onClick={loadLatest}>{t('actions.reload')}</Button>
              <Button size="small" type="primary" disabled={!tenantManage || !conflict.latest} onClick={retryAfterReload}>{t('actions.retryAfterReload')}</Button>
            </Space>
          )}
        />
      ) : null}
      {compareOpen && conflict?.latest ? (
        <div
          className="cache-policy-comparison"
          role="region"
          aria-label={t('comparison.title')}
          style={{ minWidth: 0, maxWidth: '100%', overflowX: 'clip' }}
        >
          <strong>{t('comparison.title')}</strong>
          <PolicyComparisonPanel label={t('comparison.base')} document={conflict.base} locale={i18n.resolvedLanguage} t={t} />
          <PolicyComparisonPanel label={t('comparison.latest')} document={conflict.latest.document} locale={i18n.resolvedLanguage} t={t} />
          <PolicyComparisonPanel label={t('comparison.draft')} document={conflict.draft} locale={i18n.resolvedLanguage} t={t} />
        </div>
      ) : null}
      <div className="cache-policy-status" role="status">
        {mutation.isPending ? t('states.saving') : saved ? t('states.saved') : !dirty ? t('states.unchanged') : null}
      </div>

      {draft.mode !== 'override' ? (
        <div className="cache-policy-empty">
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={<>
            <strong>{t('empty.title')}</strong>
            <span>{t('empty.description', { mode: t(`modes.${draft.mode}`) })}</span>
          </>} />
          {tenantManage ? <Button type="primary" disabled={writesLocked}
            onClick={() => setRuleDialog({ index: null, rule: newRule })}>{t('empty.add')}</Button> : null}
        </div>
      ) : (
        <section className="cache-policy-section cache-policy-rules-section" aria-label={t('fields.rules')}>
          <Table<CachePolicyRule>
            rowKey={(rule) => String(rule.order)}
            size="small"
            pagination={false}
            dataSource={draft.rules}
            columns={ruleColumns}
            scroll={{ x: 640 }}
            locale={{ emptyText: t('validation.ruleRequired') }}
          />
        </section>
      )}

      <section className="cache-policy-section" aria-labelledby="cache-policy-other-title">
        <div className="cache-policy-section-heading">
          <div><h3 id="cache-policy-other-title">{t('other.title')}</h3><p>{t('other.description')}</p></div>
        </div>
        <div className="cache-policy-mode">
        <span id="cache-policy-mode-title">{t('fields.mode')}</span>
        <Radio.Group
          aria-label={t('fields.mode')}
          value={draft.mode}
          disabled={!tenantManage || editLocked}
          onChange={(event) => updateDraft(modeDocument(draft, event.target.value as CachePolicyMode))}
        >
          {(['disabled', 'follow_origin', 'override'] as const).map((mode) => (
            <Radio key={mode} value={mode}>
              <span>{t(`modes.${mode}`)}</span>
              <small>{t(`modeHelp.${mode}`)}</small>
            </Radio>
          ))}
        </Radio.Group>
        </div>

        {extra}
        <div className="cache-policy-form-grid">
        <label>
          <span>{t('fields.queryMode')}</span>
          <Select
            value={draft.query_mode}
            aria-label={t('fields.queryMode')}
            disabled={!tenantManage || editLocked}
            options={(['preserve', 'ignore', 'include', 'exclude'] as const).map((value) => ({ value, label: t(`queryModes.${value}`) }))}
            onChange={(value: CacheQueryMode) => updateDraft({ ...draft, query_mode: value, query_names: value === 'include' || value === 'exclude' ? draft.query_names : [] })}
          />
        </label>
        {draft.query_mode === 'include' || draft.query_mode === 'exclude' ? (
          <label>
            <span>{t('fields.queryNames')}</span>
            <Input aria-label={t('fields.queryNames')} value={draft.query_names.join(', ')} disabled={!tenantManage || editLocked} onChange={(event) => updateDraft({ ...draft, query_names: commaValues(event.target.value) })} />
          </label>
        ) : null}
        </div>
      </section>

      <section className="cache-policy-section" aria-labelledby="cache-policy-advanced-title">
        <div className="cache-policy-section-heading">
          <div><h3 id="cache-policy-advanced-title">{t('advanced.title')}</h3><p>{t('advanced.description')}</p></div>
          <Button
            type="text"
            icon={advancedOpen ? <ChevronUp size={15} aria-hidden="true" /> : <ChevronDown size={15} aria-hidden="true" />}
            aria-expanded={advancedOpen}
            aria-controls="cache-policy-advanced-panel"
            onClick={() => setAdvancedOpen((value) => !value)}
          >
            {t(advancedOpen ? 'actions.hideAdvanced' : 'actions.showAdvanced')}
          </Button>
        </div>
        <div id="cache-policy-advanced-panel" className="cache-policy-form-grid" hidden={!advancedOpen}>
            <div className="cache-policy-field">
              <span>{t('fields.varyHeaders')}</span>
              <Select
                mode="tags"
                aria-label={t('fields.varyHeaders')}
                value={draft.vary_headers}
                disabled={!tenantManage || editLocked}
                tokenSeparators={[',', ' ']}
                placeholder={t('placeholders.varyHeaders')}
                options={commonVaryHeaders.map((value) => ({ value, label: t(`varyHeaderOptions.${value}`) }))}
                onChange={(values: string[]) => updateDraft({ ...draft, vary_headers: [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))] })}
              />
              <small>{t('help.varyHeaders')}</small>
            </div>
            <div className="cache-policy-field">
              <span>{t('fields.diskQuotaBytes')}</span>
              <ByteSizeInput
                label={t('fields.diskQuotaBytes')}
                value={draft.disk_quota_bytes}
                units={['mb', 'gb', 'tb']}
                max={maxQuota}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled'}
                onChange={(bytes) => updateDraft({ ...draft, disk_quota_bytes: bytes })}
              />
              <small>{t('help.diskQuota', { min: '64 MB', max: '16 TB' })}</small>
            </div>
            <label className="cache-policy-switch">
              <span>{t('fields.staleIfError')}</span>
              <Switch
                aria-label={t('fields.staleIfError')}
                checked={draft.stale_if_error ?? false}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled'}
                onChange={(checked) => updateDraft({ ...draft, stale_if_error: checked, background_update: checked && draft.background_update })}
              />
              <small>{t('help.staleIfError')}</small>
            </label>
            <label className="cache-policy-switch">
              <span>{t('fields.backgroundUpdate')}</span>
              <Switch
                aria-label={t('fields.backgroundUpdate')}
                checked={draft.background_update ?? false}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled' || !draft.stale_if_error}
                onChange={(checked) => updateDraft({ ...draft, background_update: checked })}
              />
              <small>{t('help.backgroundUpdate')}</small>
            </label>
            <div className="cache-policy-field">
              <span>{t('fields.minObjectBytes')}</span>
              <ByteSizeInput
                label={t('fields.minObjectBytes')}
                value={draft.min_object_bytes ?? 0}
                units={['kb', 'mb', 'gb']}
                max={cacheMaxObjectBytesLimit}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled'}
                onChange={(bytes) => updateDraft({ ...draft, min_object_bytes: bytes })}
              />
            </div>
            <div className="cache-policy-field">
              <span>{t('fields.maxObjectBytes')}</span>
              <ByteSizeInput
                label={t('fields.maxObjectBytes')}
                value={draft.max_object_bytes ?? 0}
                units={['kb', 'mb', 'gb']}
                max={cacheMaxObjectBytesLimit}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled'}
                onChange={(bytes) => updateDraft({ ...draft, max_object_bytes: bytes })}
              />
              <small>{t('help.objectBytes')}</small>
            </div>
            <label>
              <span>{t('fields.sliceBytes')}</span>
              <Select
                aria-label={t('fields.sliceBytes')}
                value={draft.slice_bytes ?? 0}
                disabled={!tenantManage || editLocked || draft.mode === 'disabled'}
                options={[0, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20].map((value) => ({
                  value, label: value === 0 ? t('slice.off') : t('slice.size', { size: value >= 1 << 20 ? `${value >> 20} MiB` : `${value >> 10} KiB` }),
                }))}
                onChange={(value: number) => updateDraft({ ...draft, slice_bytes: value })}
              />
              <small>{t('help.sliceBytes')}</small>
            </label>
        </div>
      </section>

      {tenantRead ? (
        <section className="cache-policy-section cache-policy-flush-section" aria-labelledby="cache-policy-flush-title">
          <div className="cache-policy-section-heading">
            <div><h3 id="cache-policy-flush-title">{t('flush.title')}</h3><p>{t('flush.description')}</p></div>
            <Popconfirm
              title={t('flush.confirm')}
              okText={t('flush.action')}
              cancelText={t('actions.cancel')}
              disabled={!tenantManage || flushMutation.isPending}
              onConfirm={() => flushMutation.mutate(flushAttempt())}
            >
              <Button danger disabled={!tenantManage || flushMutation.isPending} loading={flushMutation.isPending}>
                {t('flush.action')}
              </Button>
            </Popconfirm>
          </div>
          {flushMutation.isError ? (
            flushUncertain ? (
              <OutcomeUnknown title={tOps('groups.unknownReason')} action={
                <Button size="small" disabled={!tenantManage || flushMutation.isPending}
                  onClick={() => flushMutation.mutate(flushAttempt())}>{t('actions.retry')}</Button>} />
            ) : <FeedbackWhen title={flushMutation.error === flushSessionChanged
              ? localError(flushMutation.error, t) : flushError(flushMutation.error, tOps)} />
          ) : null}
          {flushMutation.isSuccess ? (
            <Alert type="success" showIcon message={t('flush.done')} />
          ) : null}
        </section>
      ) : null}

        <section
          id="cache-policy-history-panel"
          className="cache-policy-history"
          role="region"
          aria-label={t('history.title')}
          hidden={!historyOpen}
        >
          <h3>{t('history.title')}</h3>
          {historyQuery.isError ? <FeedbackWhen title={localError(historyQuery.error, t)} /> : null}
          <Table
            rowKey="revision"
            size="small"
            loading={historyQuery.isPending || historyQuery.isFetching}
            columns={historyColumns}
            dataSource={historyQuery.data?.items ?? []}
            pagination={false}
            locale={{ emptyText: historyQuery.isPending ? ' ' : t('history.empty') }}
          />
          <div className="cache-policy-pagination">
            <Button disabled={historyStack.length === 0 || historyQuery.isFetching} onClick={() => { const next = historyStack.slice(0, -1); setHistoryStack(next); setHistoryCursor(next.at(-1)) }}>{t('actions.previous')}</Button>
            <Button disabled={!historyQuery.data?.next_cursor || historyQuery.isFetching} onClick={() => { const next = historyQuery.data?.next_cursor; if (next) { setHistoryStack((value) => [...value, next]); setHistoryCursor(next) } }}>{t('actions.next')}</Button>
          </div>
          {selectedHistory ? (
            <div className="cache-policy-history-detail">
              <strong>{t('history.revision')} {selectedHistory.revision}</strong>
              <span>{t('history.createdBy')}: {selectedHistory.created_by_user_id}</span>
              <span>{t('history.requestId')}: {selectedHistory.request_id}</span>
              <span>{t('fields.mode')}: {t(`modes.${selectedHistory.document.mode}`)}</span>
              <span>{t('fields.queryMode')}: {t(`queryModes.${selectedHistory.document.query_mode}`)}</span>
            </div>
          ) : null}
          {historyDetailError ? (
            <FeedbackWhen title={t('history.detailError')} detail={localError(historyDetailError, t)} action={historyDetailRevision === undefined ? undefined : (
                <Button size="small" onClick={() => void loadHistoryRevision(historyDetailRevision)}>{t('actions.retry')}</Button>
              )} />
          ) : null}
        </section>
      {ruleDialog ? (
        <CacheRuleDialog
          open
          rule={ruleDialog.rule}
          editing={ruleDialog.index !== null}
          inheritedIgnoreQuery={draft.query_mode === 'ignore'}
          inheritedSliceBytes={draft.slice_bytes ?? 0}
          disabled={!tenantManage || editLocked}
          serverError={ruleDialog.error}
          onCancel={() => setRuleDialog(null)}
          onSubmit={submitRule}
        />
      ) : null}
    </section>
  )
}

export default function CacheSiteTab(props: CacheSiteTabProps) {
  const ownerKey = JSON.stringify([
    props.sessionEpoch,
    props.userId,
    props.scopeKind,
    props.scopeId,
    props.tenantId,
    props.siteId,
    props.siteScopeId,
  ])
  return <CacheSiteTabOwned key={ownerKey} {...props} />
}
