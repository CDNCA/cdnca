import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App,
  Button,
  Dropdown,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Result,
  Select,
  Spin,
  Switch,
  Table,
  Tag,
  Tooltip,
  type MenuProps,
  type TableColumnsType,
} from 'antd'
import { ChevronDown, ChevronLeft, ChevronRight, Copy, Download, Ellipsis, Lock } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import { usersApi, type ManagedUser } from '../api/users'
import { siteGroupsApi } from '../api/siteGroups'
import { dnsApi } from '../api/dns'
import {
  canonicalSiteDomains,
  sitesApi,
  operationalSiteStatus,
  type BatchSiteAction,
  type BatchSiteActionItemResult,
  type BatchSiteActionRequest,
  type BatchSiteActionResponse,
  type CreateSiteRequest,
  type LockSiteRequest,
  type OriginBalanceMethod,
  type OriginScheme,
  type SiteOrigin,
  type SiteOriginPool,
  type SiteDetail,
  type SiteListItem,
  type SiteListParams,
  type SiteListResponse,
  type SiteOperationalStatus,
  type SiteStatus,
  type UnlockSiteRequest,
} from '../api/sites'
import { roleForPrincipal, useSessionStore } from '../auth/session'
import { useRuntimeFeatureOff } from '../components/useRuntimeFeatures'
import { DomainOwnershipPanel } from './domain-trust/DomainOwnershipPanel'
import { ResourceID } from '../components/ResourceID'
import TenantScopeSelect from '../components/TenantScopeSelect'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/siteCnameRegeneration'
import { cnameFailureText, siteAccessGap } from './site-edit/cnameFailureText'
import { SiteAccessStatus } from './site-edit/SiteAccessReadiness'
import CnameFailureActions from './site-edit/CnameFailureActions'
import SiteTransferModal from './site-edit/SiteTransferModal'
import '../i18n/siteCreate'
import '../i18n/siteDomainExport'
import '../i18n/domainTrust'
import '../i18n/siteListTabs'
import {
  clearSiteBatchRetry,
  persistSiteBatchRetry,
  restoreSiteBatchRetry,
  siteBatchRetryStorageKey,
  type SiteBatchAttempt,
  type SiteBatchRetryLockState,
} from './siteBatchRetryLock'
import {
  clearSiteCreateRetry,
  persistSiteCreateRetry,
  restoreSiteCreateRetry,
  siteCreateRetryStorageKey,
} from './siteCreateRetryLock'
import './SiteCreateModal.css'
import './SiteListPage.typography.css'
import SiteAutomaticFailureNotice from './SiteAutomaticFailureNotice'
import SiteGroupsPage from './SiteGroupsPage'
import SiteDnsApiPanel from './SiteDnsApiPanel'
import SiteDefaultsPanel from './SiteDefaultsPanel'
import SiteDnsCheckPanel, { type SiteDnsCheckContext } from './SiteDnsCheckPanel'
import SiteHttpsQuickModal from './SiteHttpsQuickModal'
import { AdvancedFilters, FeedbackWhen, IdOrNameInput, OutcomeUnknown, useLiveApply, type AdvancedFilterItem } from '@cdnca/ui'
import { filterParam, useFilterUrl } from './filterUrl'
import { siteSearch, userSearch } from './idNameSources'

type SiteFilters = Omit<SiteListParams, 'page' | 'limit'>

const siteUUIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// 网站ID 未选联想项时按名称过滤——site_ids 里不是
// UUID 列表的文本改发 site（域名或展示 ID）。
function siteRequestFilters(filters: SiteFilters): SiteFilters {
  const next = { ...filters }
  const ids = next.site_ids?.split(/[\s,]+/).filter(Boolean) ?? []
  if (ids.length > 0 && !ids.every((id) => siteUUIDPattern.test(id))) {
    next.site = next.site_ids
    delete next.site_ids
  }
  return next
}
type SiteQuickField =
  | 'domain'
  | 'domains'
  | 'origin_ip'
  | 'site_ids'
  | 'owner'
  | 'region_id'
  | 'node_group_id'
  | 'cname_domain'
  | 'cname_hostname'
  | 'http_port'
  | 'https_port'
  | 'https_enabled'
  | 'enabled'
  | 'is_default'
  | 'sync_status'
  | 'status'
type Dialog = 'create' | 'batch' | null
type SiteCreateMode = 'single' | 'batch'
type LockAction = 'lock' | 'unlock'
type SiteStatusTarget = Pick<SiteListItem, 'id' | 'domain' | 'version'>
type SitePermission = 'sites.read' | 'sites.manage' | 'sites.export' | 'dns.manage' | 'dns.read'
  | 'identity.users.manage' | 'billing.adjustments.manage' | 'package_subscriptions.read'
type SiteSessionOwner = readonly [Principal['scope_kind'], string, string | null, string, number]

interface LockAttempt {
  action: LockAction
  id: string
  input: LockSiteRequest | UnlockSiteRequest
  key: string
  owner: SiteSessionOwner
  ownerKey: string
}

interface LockDialogState {
  action: LockAction
  item: SiteListItem
  detail: SiteDetail | null
  loading: boolean
  reason: string
  error: ApiError | null
  attempt: LockAttempt | null
  reloadRequired: boolean
  stateMismatch: boolean
}

interface SiteStatusAttempt {
  status: SiteOperationalStatus
  targets: SiteStatusTarget[]
  reason: string
  key: string
  owner: SiteSessionOwner
  ownerKey: string
}

interface SiteStatusDialogState {
  attempt: SiteStatusAttempt
  error: ApiError | null
}

interface BatchResultState {
  attempt: SiteBatchAttempt
  items: BatchSiteActionItemResult[]
}

interface SiteCreateAttempt {
  input: CreateSiteRequest
  key: string
  body: string
  owner: SiteSessionOwner
  ownerKey: string
}

interface SiteBatchCreateResult {
  saved: SiteDetail[]
  failed: Array<{ domain: string; error: unknown }>
}

interface SiteBatchWriteAttempt {
  attempt: SiteBatchAttempt
  owner: SiteSessionOwner
  ownerKey: string
}

type SiteOperationNotice =
  | {
      type: 'success'
      namespace: 'sites'
      key: 'lock.successLocked' | 'lock.successUnlockQueued' | 'lock.successUnlocked' | 'status.success'
      domain: string
      count?: number
    }
  | {
      type: 'success'
      namespace: 'siteCreate'
      key: 'success'
      domain: string
      // C09: the created site, for the "view site" button (batch: the first saved one).
      siteID?: string
    }

type SiteExportNotice =
  | { type: 'success'; key: 'success' }
  | { type: 'error'; key: 'errors.platformTargetRequired' | 'errors.forbidden' | 'errors.failed' }

const pageSizes = [10, 20, 50, 100]
const staleSiteAttempt = new Error('Site session changed')

const siteStatus: Record<SiteStatus | 'normal', { color: string }> = {
  normal: { color: 'success' },
  active: { color: 'success' },
  disabled: { color: 'default' },
  package_expired: { color: 'warning' },
  traffic_exceeded: { color: 'warning' },
  locked: { color: 'error' },
  syncing: { color: 'processing' },
  sync_failed: { color: 'error' },
}

function joinValues(values: string[], language: string, placeholder: string): string {
  return values.length > 0 ? values.join(language === 'en-US' ? ', ' : '、') : placeholder
}

// 按实测内容宽度（14px 字号，单元格左右内边距各 8px）规划的列宽。1440 下表格可用
// 约 1100（Windows 竖向滚动条再占 17），管理员与租户合计都按 1080 排，1440 起不出横向滚动，
// 更宽时各列按比例放宽。1280 下可用约 940，保留横向滚动，操作列固定在右侧。
// 域名、CNAME、源站、分组、区域放不下时省略并悬浮看全。
const siteListColumnWidths = {
  selection: 32,
  id: 52,
  domain: { admin: 150, user: 150 },
  cname: { admin: 148, user: 230 },
  https: 62,
  originListen: { admin: 134, user: 132 },
  group: 120,
  region: 74,
  status: 66,
  createdAt: 90,
  actions: 76,
} as const

function siteListTableWidth(role: 'admin' | 'user'): number {
  const w = siteListColumnWidths
  return w.selection + w.id + w.domain[role] + w.cname[role] + w.https + w.originListen[role] + w.group +
    (role === 'admin' ? w.region : 0) + w.status + w.createdAt + w.actions
}

function displayDate(value: string, language: string, placeholder: string): string {
  const formatted = formatDateTime(value, language)
  if (!formatted) return value || placeholder
  return language === 'zh-CN' ? formatted.replaceAll('/', '-') : formatted
}

function writeOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

// Batch 500s confirmed (by the targets' versions) not to have
// written anything; shown as failures instead of unknown outcomes.
const batchNotApplied = new WeakSet<object>()

async function settleBatchOutcome(
  token: string,
  attempt: SiteBatchAttempt,
): Promise<BatchSiteActionResponse | 'not_applied' | null> {
  const listed = await sitesApi.list(token, {
    page: 1,
    limit: 100,
    site_ids: attempt.targets.map((target) => target.id).join(','),
  })
  const versions = new Map(listed.items.map((item) => [item.id, item.version]))
  if (attempt.targets.every((target) => versions.get(target.id) === target.version)) return 'not_applied'
  return sitesApi.batchAction(token, attempt.input, attempt.key, attempt.body)
}

function terminalSiteAuthorizationError(error: unknown): boolean {
  return error instanceof ApiError &&
    error.status === 403 &&
    (error.code === 'permission_denied' || error.code === 'forbidden')
}

function siteSessionOwner(principal: Principal, sessionEpoch: number): SiteSessionOwner | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'tenant' && !principal.tenant_id) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  return [
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
  ]
}

function sitePrincipalCan(principal: Principal, permission: SitePermission): boolean {
  return principal.permissions.includes(permission) || (
    principal.scope_kind === 'platform' && principal.permissions.includes('platform.admin')
  )
}

function currentSiteSessionAccess(ownerKey: string, permission: SitePermission): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !sitePrincipalCan(principal, permission)) return null
  const owner = siteSessionOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function lockActionMatches(action: LockAction, detail: SiteDetail): boolean {
  return action === 'lock' ? !detail.lock.locked : detail.lock.locked
}

function writeKey(action: string, id?: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return ['site', action, id, suffix].filter(Boolean).join('-')
}

function normalizeSiteDomain(raw: string, wildcard: boolean): string | null {
  let domain = raw.trim().toLowerCase()
  if (domain.endsWith('.')) domain = domain.slice(0, -1)
  const hasWildcard = domain.startsWith('*.')
  if (hasWildcard && !wildcard) return null
  const base = hasWildcard ? domain.slice(2) : domain
  if (
    domain.length > 253 ||
    base.length === 0 ||
    /[/:@\s\\[\]]/.test(base)
  ) {
    return null
  }
  const labels = base.split('.')
  if (labels.length < 2) return null
  if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    return null
  }
  return hasWildcard ? `*.${base}` : base
}

function normalizeUUID(raw: string): string | null {
  const value = raw.trim().toLowerCase()
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value) ||
    value === '00000000-0000-0000-0000-000000000000'
  ) {
    return null
  }
  return value
}

function normalizeIPv4(raw: string): string | null {
  if (!/^\d+(?:\.\d+){3}$/.test(raw)) return null
  const octets = raw.split('.').map(Number)
  if (octets.some((octet) =>
    !Number.isInteger(octet) ||
    octet < 0 ||
    octet > 255,
  )) return null
  if (
    octets.every((octet) => octet === 0) ||
    (octets[0] >= 224 &&
      octets[0] <= 239)
  ) return null
  return octets.join('.')
}

function normalizeIPv6(raw: string): string | null {
  if (!raw.includes(':') || raw.includes('%')) return null
  try {
    const hostname = new URL(`http://[${raw}]/`).hostname
    if (!hostname.startsWith('[') || !hostname.endsWith(']')) return null
    const address = hostname.slice(1, -1).toLowerCase()
    if (address === '::' || address.startsWith('ff')) return null
    return address
  } catch {
    return null
  }
}

function normalizeOrigin(raw: string): string | null {
  const value = raw.trim().toLowerCase()
  if (value.length === 0 || value.length > 512 || /[/\\?#@\s]/.test(value)) return null

  let host = value
  let port = 80
  let ipv6 = false
  if (value.startsWith('[')) {
    const closing = value.indexOf(']')
    if (closing < 0) return null
    const suffix = value.slice(closing + 1)
    if (suffix !== '' && !suffix.startsWith(':')) return null
    host = value.slice(1, closing)
    if (suffix.startsWith(':')) {
      if (!/^\d+$/.test(suffix.slice(1))) return null
      port = Number(suffix.slice(1))
    }
    const address = normalizeIPv6(host)
    if (!address) return null
    host = address
    ipv6 = true
  } else if ((value.match(/:/g) ?? []).length > 1) {
    const address = normalizeIPv6(value)
    if (!address) return null
    host = address
    ipv6 = true
  } else {
    const separator = value.indexOf(':')
    if (separator >= 0) {
      host = value.slice(0, separator)
      const rawPort = value.slice(separator + 1)
      if (!/^\d+$/.test(rawPort)) return null
      port = Number(rawPort)
    }
    const address = normalizeIPv4(host)
    if (address) host = address
    else {
      if (/^\d+(?:\.\d+){3}$/.test(host)) return null
      const domain = normalizeSiteDomain(host, false)
      if (!domain) return null
      host = domain
    }
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return null
  if (port === 80) return host
  return ipv6 ? `[${host}]:${port}` : `${host}:${port}`
}

function normalizePortList(raw: string): string[] | null {
  const values = raw.trim() === '' ? [] : raw.split(/[\s,]+/u)
  if (values.length > 32) return null
  const result: string[] = []
  const seen = new Set<string>()
  for (const rawPort of values) {
    if (!/^\d+$/u.test(rawPort)) return null
    const port = Number(rawPort)
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return null
    const canonical = String(port)
    if (seen.has(canonical)) return null
    seen.add(canonical)
    result.push(canonical)
  }
  return result
}

function originPoolOrigin(endpoint: string): SiteOrigin | null {
  if (endpoint.startsWith('[')) {
    const closing = endpoint.indexOf(']')
    const host = endpoint.slice(1, closing)
    const port = Number(endpoint.slice(closing + 2))
    return closing > 0 && Number.isInteger(port)
      ? { host, port, weight: 1, enabled: true }
      : null
  }
  if ((endpoint.match(/:/g) ?? []).length > 1) {
    return { host: endpoint, port: 80, weight: 1, enabled: true }
  }
  const separator = endpoint.lastIndexOf(':')
  return separator > 0
    ? { host: endpoint.slice(0, separator), port: Number(endpoint.slice(separator + 1)), weight: 1, enabled: true }
    : { host: endpoint, port: 80, weight: 1, enabled: true }
}

function parseManualBatchTargets(raw: string): SiteBatchAttempt['targets'] | null {
  const lines = raw.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
  if (lines.length < 1 || lines.length > 100) return null
  const targets: SiteBatchAttempt['targets'] = []
  const seen = new Set<string>()
  for (const line of lines) {
    const match = line.match(/^([^,]+),\s*([^,]+)$/u)
    const id = match ? normalizeUUID(match[1] ?? '') : null
    const version = match && /^(?:0*[1-9]\d*)$/u.test(match[2] ?? '') ? Number(match[2]) : 0
    if (!id || !Number.isSafeInteger(version) || version < 1 || seen.has(id)) return null
    seen.add(id)
    targets.push({ id, domain: id, version })
  }
  return targets
}

interface SiteBatchCreateRow {
  domain: string
  origin: string
}

function parseSiteBatchCreateRows(raw: string): SiteBatchCreateRow[] | null {
  const lines = raw.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean)
  if (lines.length < 1 || lines.length > 100) return null
  const rows: SiteBatchCreateRow[] = []
  for (const line of lines) {
    const fields = new Map<string, string>()
    for (const part of line.split('|')) {
      const separator = part.indexOf('=')
      if (separator > 0) fields.set(part.slice(0, separator).trim().toLowerCase(), part.slice(separator + 1).trim())
    }
    const domain = fields.get('domain') ?? fields.get('domains') ?? ''
    const origin = fields.get('ip') ?? fields.get('origin') ?? fields.get('origins') ?? ''
    if (!domain || !origin) return null
    rows.push({ domain, origin })
  }
  return rows
}

// The domain an ownership refusal is about: a wildcard is what needs proof
// under the default policy, otherwise the first domain entered.
function ownershipDomain(raw: string): string {
  const domains = raw.split(/[\n,]+/u).map((item) => item.trim()).filter(Boolean)
  return domains.find((item) => item.startsWith('*.')) ?? domains[0] ?? ''
}

function createErrorMessage(code: string, t: TFunction<'siteCreate'>, field?: string): string {
  // PJ-C05：服务端点名了字段时说清是哪一项（未收录的字段用通用文案）。
  if (code === 'validation_error' && field) {
    const text = t(`errors.fields.${field}`, { defaultValue: '' })
    if (text) return text
  }
  switch (code) {
    case 'site_domain_conflict':
    case 'domain_blocked':
    case 'domain_verified_by_other':
    case 'domain_ownership_required':
    case 'validation_error':
    case 'permission_denied':
    case 'idempotency_conflict':
    case 'entitlement_denied':
    case 'entitlement_unavailable':
    case 'entitlement_state_denied':
    case 'entitlement_feature_denied':
    case 'entitlement_quota_denied':
    case 'entitlement_quota_exceeded':
      return t(`errors.${code}`)
    default:
      return t('errors.request_failed')
  }
}

function errorCodeMessage(code: string, t: TFunction<'sites'>): string {
  switch (code) {
    case 'version_conflict':
    case 'site_lock_state_conflict':
    case 'site_domain_claim_suspended':
    case 'package_subscription_inactive':
    case 'package_resource_quota_exceeded':
    case 'package_feature_denied':
    case 'validation_error':
    case 'site_not_found':
    case 'retry_lock_corrupted':
      return t(`errors.${code}`)
    case 'network_error':
      return t('errors.operationFailed')
    case 'request_failed':
      return t('errors.requestFailed')
    case 'permission_denied':
      return t('errors.forbiddenDescription')
    default:
      return t('errors.operationFailed')
  }
}

function cnameErrorCodeMessage(
  code: string,
  t: TFunction<'siteCnameRegeneration'>,
): string {
  switch (code) {
    case 'cname_not_configured':
    case 'cname_not_failed':
    case 'cname_not_regenerable':
    case 'permission_denied':
    case 'site_not_found':
    case 'site_locked':
    case 'version_conflict':
      return t(`errors.${code}`)
    default:
      return t('errors.request_failed')
  }
}

function siteOperationNoticeMessage(
  notice: SiteOperationNotice,
  t: TFunction<'sites'>,
  tCreate: TFunction<'siteCreate'>,
): string {
  if (notice.namespace === 'siteCreate') return tCreate('success', { domain: notice.domain })
  return t(notice.key, { domain: notice.domain, count: notice.count })
}

function siteExportNoticeMessage(
  notice: SiteExportNotice,
  tExport: TFunction<'siteDomainExport'>,
): string {
  switch (notice.key) {
    case 'success':
      return tExport('success')
    case 'errors.platformTargetRequired':
      return tExport('errors.platformTargetRequired')
    case 'errors.forbidden':
      return tExport('errors.forbidden')
    case 'errors.failed':
      return tExport('errors.failed')
  }
  return tExport('errors.failed')
}

function AdvancedField({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="site-filter-field">
      <span>{label}</span>
      {children}
    </label>
  )
}

function SiteBatchInputModal({
  canRegenerateCname,
  onClose,
  onPreview,
}: {
  canRegenerateCname: boolean
  onClose: () => void
  onPreview: (action: BatchSiteAction, targets: SiteBatchAttempt['targets']) => void
}) {
  const { t } = useTranslation('sites')
  const { t: tCname } = useTranslation('siteCnameRegeneration')
  const [action, setAction] = useState<BatchSiteAction>('enable')
  const [raw, setRaw] = useState('')
  const [invalid, setInvalid] = useState(false)

  const preview = () => {
    const targets = parseManualBatchTargets(raw)
    if (!targets) {
      setInvalid(true)
      return
    }
    onPreview(action, targets)
  }

  return (
    <Modal
      className="site-action-modal"
      title={t('unsupported.batchTitle')}
      open
      width={560}
      okText={t('batch.preview')}
      cancelText={t('actions.cancel')}
      okButtonProps={{ disabled: raw.trim() === '' }}
      onCancel={onClose}
      onOk={preview}
    >
      <div className="site-create-form">
        <AdvancedField label={t('batch.actionLabel')}>
          <Select
            aria-label={t('batch.actionLabel')}
            value={action}
            options={[
              { value: 'enable', label: t('actions.batchEnable') },
              { value: 'disable', label: t('actions.batchDisable') },
              { value: 'delete', label: t('actions.batchDelete') },
              ...(canRegenerateCname ? [{ value: 'regenerate_cname', label: tCname('action') }] : []),
            ]}
            onChange={(value) => {
              setAction(value)
              setInvalid(false)
            }}
          />
        </AdvancedField>
        <AdvancedField label={t('batch.inputLabel')}>
          <Input.TextArea
            aria-label={t('batch.inputLabel')}
            value={raw}
            rows={7}
            status={invalid ? 'error' : undefined}
            placeholder={t('batch.inputPlaceholder')}
            onChange={(event) => {
              setRaw(event.target.value)
              setInvalid(false)
            }}
          />
          {invalid ? <small>{t('batch.inputInvalid')}</small> : null}
        </AdvancedField>
        <Alert showIcon type="info" message={t('batch.inputHelp')} />
      </div>
    </Modal>
  )
}

function SiteCreateModal({
  platform,
  owner,
  ownerKey,
  sessionAccess: ownerSessionAccess,
  onClose,
  onCreated,
  onForbidden,
}: {
  platform: boolean
  owner: SiteSessionOwner
  ownerKey: string
  sessionAccess: (permission: SitePermission) => string | null
  onClose: () => void
  onCreated: (domain: string, siteID?: string) => void
  onForbidden: () => void
}) {
  const { t } = useTranslation('siteCreate')
  const { t: tTabs } = useTranslation('siteListTabs')
  const queryClient = useQueryClient()
  const activeRef = useRef(true)
  useEffect(() => {
    activeRef.current = true
    return () => { activeRef.current = false }
  }, [])
  const sessionAccess = (permission: SitePermission) => activeRef.current ? ownerSessionAccess(permission) : null
  const retryStorageKey = `${siteCreateRetryStorageKey(owner[1], owner[3])}:${owner[0]}:${encodeURIComponent(owner[2] ?? 'null')}`
  const [restoredBatch] = useState(() => restoreSiteCreateRetry(retryStorageKey))
  const [batchUncertain, setBatchUncertain] = useState(Boolean(restoredBatch.items))
  const [storageBlocked, setStorageBlocked] = useState(restoredBatch.corrupted)
  const [mode, setMode] = useState<SiteCreateMode>(restoredBatch.items ? 'batch' : 'single')
  const [selectedUser, setSelectedUser] = useState<ManagedUser | null>(null)
  const [userSearch, setUserSearch] = useState('')
  const targetScope = platform ? selectedUser?.scope_id ?? '' : owner[1]
  const ownerUser = platform ? selectedUser?.id ?? '' : owner[3]
  const [domain, setDomain] = useState('')
  const [origin, setOrigin] = useState('')
  const [batchData, setBatchData] = useState(() => restoredBatch.items?.map(({ input }) =>
    `domain=${input.basic.domains.join(',')}|ip=${input.basic.origins.join(',')}`).join('\n') ?? '')
  const [batchIgnoreErrors, setBatchIgnoreErrors] = useState(false)
  const [batchInvalid, setBatchInvalid] = useState(false)
  const [groupID, setGroupID] = useState('')
  const [groupName, setGroupName] = useState('')
  // 建站「DNS API（自动添加记录）」：本人已验证的 DNS 账号（租户才有）
  const [dnsProviderID, setDNSProviderID] = useState('')
  // SITE-CURRENT-01：端口与负载方式留空即不提交，由服务端按 默认设置
  // （分组 > 全局）> 系统默认 > 80 / 443 / 轮询 填；填了的优先。
  const [httpPorts, setHTTPPorts] = useState('')
  const [httpsEnabled, setHTTPSEnabled] = useState(false)
  const [httpsPorts, setHTTPSPorts] = useState('')
  const [cname, setCNAME] = useState('')
  const [balanceMethod, setBalanceMethod] = useState<OriginBalanceMethod | undefined>(undefined)
  // 回源协议与回源 Host（建站即可设置，与站点编辑页“回源设置”同一组字段）。
  // CU-SITE-02：undefined 表示未选择（不提交，按默认设置）；选了 HTTP 也要提交。
  const [originScheme, setOriginScheme] = useState<OriginScheme | undefined>(undefined)
  const [originHost, setOriginHost] = useState('')
  const [originHostInvalid, setOriginHostInvalid] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [ownerUserInvalid, setOwnerUserInvalid] = useState(false)
  const [domainInvalid, setDomainInvalid] = useState(false)
  const [originInvalid, setOriginInvalid] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [attempt, setAttempt] = useState<SiteCreateAttempt | null>(null)
  const [batchAttempt, setBatchAttempt] = useState<SiteCreateAttempt[] | null>(() =>
    restoredBatch.items?.map((item) => ({ ...item, owner, ownerKey })) ?? null)
  const [batchResult, setBatchResult] = useState<SiteBatchCreateResult | null>(null)
  const inFlightAttempt = useRef<SiteCreateAttempt | null>(null)
  const inFlightBatchAttempt = useRef<SiteCreateAttempt[] | null>(null)
  const completedBatchKeys = useRef(new Set<string>())

  const canReadUsers = Boolean(sessionAccess('identity.users.manage'))
  const canAutoDNS = !platform && Boolean(sessionAccess('dns.manage'))
  const dnsProviders = useQuery({
    queryKey: ['site-create-dns-providers', owner],
    enabled: canAutoDNS && advancedOpen,
    queryFn: async () => {
      const token = sessionAccess('dns.read')
      if (!token) throw staleSiteAttempt
      return dnsApi.list(token)
    },
  })
  const verifiedDNSProviders = (dnsProviders.data?.items ?? []).filter((item) => item.status === 'verified' && item.managed_by !== 'platform')
  const users = useInfiniteQuery({
    queryKey: ['site-create-users', owner, userSearch],
    enabled: platform && canReadUsers,
    initialPageParam: 1,
    queryFn: async ({ pageParam }) => {
      const token = sessionAccess('identity.users.manage')
      if (!token) throw staleSiteAttempt
      const result = await usersApi.list(token, { page: pageParam, limit: 20, search: userSearch, status: 'active' })
      if (!sessionAccess('identity.users.manage')) throw staleSiteAttempt
      return result
    },
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const groups = useInfiniteQuery({
    queryKey: ['site-create-groups', owner, targetScope],
    enabled: advancedOpen && Boolean(targetScope && sessionAccess('sites.read')),
    initialPageParam: 1,
    queryFn: async ({ pageParam }) => {
      const token = sessionAccess('sites.read')
      if (!token) throw staleSiteAttempt
      const result = await siteGroupsApi.list(token, targetScope, pageParam, 20)
      if (!sessionAccess('sites.read') || result.items.some((item) => item.scope_id !== targetScope)) throw staleSiteAttempt
      if (result.page !== pageParam || result.limit !== 20 || result.items.length > 20 || result.total < result.items.length) {
        throw new ApiError('Invalid group page', 502, 'invalid_response')
      }
      return result
    },
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const userOptions = users.data?.pages.flatMap((page) => page.items).filter((item) => item.status === 'active') ?? []
  const groupOptions = groups.data?.pages.flatMap((page) => page.items).filter((item) => !item.deleted_at) ?? []

  const mutation = useMutation({
    mutationKey: ['site-create', owner],
    mutationFn: async (frozen: SiteCreateAttempt) => {
      const token = frozen.ownerKey === ownerKey ? sessionAccess('sites.manage') : null
      if (!token) throw staleSiteAttempt
      try {
        const saved = await sitesApi.create(token, frozen.input, frozen.key, frozen.body)
        if (!sessionAccess('sites.manage')) throw staleSiteAttempt
        return saved
      } catch (reason) {
        if (!sessionAccess('sites.manage')) throw staleSiteAttempt
        throw reason
      }
    },
    onSuccess: async (saved, frozen) => {
      if (!sessionAccess('sites.manage')) return
      inFlightAttempt.current = null
      const createdDomain = saved.basic.domains[0] ?? ''
      setSelectedUser(null)
      setDomain('')
      setOrigin('')
      setAttempt(null)
      setError(null)
      onClose()
      onCreated(createdDomain, saved.id)
      await queryClient.invalidateQueries({ queryKey: ['sites', frozen.owner] })
    },
    onError: (reason: unknown, frozen) => {
      if (reason === staleSiteAttempt || !sessionAccess('sites.manage')) return
      inFlightAttempt.current = null
      const apiError = reason instanceof ApiError
        ? reason
        : new ApiError(t('errors.request_failed'))
      if (terminalSiteAuthorizationError(apiError)) {
        onForbidden()
        return
      }
      // PJ-C05：服务端点名的字段就地标红（域名/源站），顶部提示仍给原因。
      if (apiError.code === 'validation_error' && apiError.field === 'domains') setDomainInvalid(true)
      if (apiError.code === 'validation_error' && apiError.field === 'origins') setOriginInvalid(true)
      setError(apiError)
      setAttempt(writeOutcomeUnknown(reason) ? frozen : null)
    },
  })

  const batchMutation = useMutation({
    mutationKey: ['site-batch-create', owner],
    mutationFn: async (frozen: SiteCreateAttempt[]) => {
      if (!sessionAccess('sites.manage')) throw staleSiteAttempt
      const saved: SiteDetail[] = []
      const failed: Array<{ domain: string; error: unknown }> = []
      for (const item of frozen) {
        const token = item.ownerKey === ownerKey ? sessionAccess('sites.manage') : null
        if (!token) throw staleSiteAttempt
        try {
          const result = await sitesApi.create(token, item.input, item.key, item.body)
          if (!sessionAccess('sites.manage')) throw staleSiteAttempt
          saved.push(result)
          completedBatchKeys.current.add(item.key)
        } catch (reason) {
          if (reason === staleSiteAttempt || !sessionAccess('sites.manage')) throw staleSiteAttempt
          if (terminalSiteAuthorizationError(reason)) throw reason
          if (!batchIgnoreErrors) throw reason
          failed.push({ domain: item.input.basic.domains[0] ?? '', error: reason })
        }
      }
      return { saved, failed }
    },
    onSuccess: async (result, frozen) => {
      if (!sessionAccess('sites.manage')) return
      inFlightBatchAttempt.current = null
      setBatchResult(result)
      setError(null)
      if (result.failed.length > 0) {
        const failedDomains = new Set(result.failed.map((item) => item.domain))
        const remaining = frozen.filter((item) => failedDomains.has(item.input.basic.domains[0] ?? ''))
        setBatchAttempt(remaining)
        setBatchData(remaining.map(({ input }) => `domain=${input.basic.domains.join(',')}|ip=${input.basic.origins.join(',')}`).join('\n'))
        if (batchUncertain || result.failed.some((item) => writeOutcomeUnknown(item.error))) {
          setBatchUncertain(true)
          if (!persistSiteCreateRetry(retryStorageKey, remaining.map(({ input, key, body }) => ({ input, key, body })))) {
            setStorageBlocked(true)
          }
        } else if (!clearSiteCreateRetry(retryStorageKey)) setStorageBlocked(true)
      } else {
        if (!clearSiteCreateRetry(retryStorageKey)) {
          setStorageBlocked(true)
          return
        }
        setBatchAttempt(null)
        setBatchUncertain(false)
        onClose()
        if (result.saved.length > 0) onCreated(result.saved[0]?.basic.domains[0] ?? '', result.saved[0]?.id)
      }
      await queryClient.invalidateQueries({ queryKey: ['sites', frozen[0]?.owner] })
    },
    onError: (reason: unknown, frozen) => {
      if (reason === staleSiteAttempt || !sessionAccess('sites.manage')) return
      inFlightBatchAttempt.current = null
      const apiError = reason instanceof ApiError ? reason : new ApiError(t('errors.request_failed'))
      if (terminalSiteAuthorizationError(apiError)) {
        onForbidden()
        return
      }
      const remaining = frozen.filter((item) => !completedBatchKeys.current.has(item.key))
      if (writeOutcomeUnknown(reason) || batchUncertain) {
        setBatchUncertain(true)
        if (!persistSiteCreateRetry(retryStorageKey, remaining.map(({ input, key, body }) => ({ input, key, body })))) setStorageBlocked(true)
      } else if (!clearSiteCreateRetry(retryStorageKey)) setStorageBlocked(true)
      setError(apiError)
      setBatchAttempt(remaining)
      setBatchData(remaining.map(({ input }) => `domain=${input.basic.domains.join(',')}|ip=${input.basic.origins.join(',')}`).join('\n'))
    },
  })

  const changeDomain = (value: string) => {
    setDomain(value)
    setDomainInvalid(false)
    setFormError(null)
    setError(null)
    setAttempt(null)
    setBatchInvalid(false)
    setBatchResult(null)
  }
  const changeOwnerUser = (value: string) => {
    setSelectedUser(userOptions.find((item) => item.id === value) ?? null)
    setGroupID('')
    setGroupName('')
    setOwnerUserInvalid(false)
    setFormError(null)
    setError(null)
    setAttempt(null)
    setBatchAttempt(null)
    setBatchInvalid(false)
    setBatchResult(null)
  }
  const changeOrigin = (value: string) => {
    setOrigin(value)
    setOriginInvalid(false)
    setFormError(null)
    setError(null)
    setAttempt(null)
    setBatchInvalid(false)
    setBatchResult(null)
  }
  const changeAdditional = (change: () => void) => {
    change()
    setFormError(null)
    setError(null)
    setAttempt(null)
    setBatchAttempt(null)
    setBatchResult(null)
  }

  const validateResourceSelection = () => {
    if (platform && (!sessionAccess('identity.users.manage') || !selectedUser || selectedUser.status !== 'active')) {
      setOwnerUserInvalid(true)
      return false
    }
    if (groupID && (groups.isError || !groupOptions.some((item) => item.id === groupID && item.name === groupName))) {
      setFormError(t('validation.references'))
      return false
    }
    return true
  }

  // 未选择不发送（按默认设置，再按后端默认 HTTP 回源、访客 Host）；回源 Host 填写即 custom。字符集与后端 normalizeRequestHost 一致。
  const originForwarding = (): Pick<SiteOriginPool, 'scheme' | 'request_host'> | null => {
    const host = originHost.trim().toLowerCase()
    const invalid = host.length > 259 || /[\s$/\\?#@"'{};]/u.test(host)
    setOriginHostInvalid(invalid)
    if (invalid) {
      setAdvancedOpen(true)
      return null
    }
    return {
      ...(originScheme ? { scheme: originScheme } : {}),
      ...(host ? { request_host: { mode: 'custom' as const, value: host } } : {}),
    }
  }

  const submitBatch = () => {
    if (storageBlocked || inFlightBatchAttempt.current || !sessionAccess('sites.manage')) return
    let frozen = batchAttempt
    if (!frozen) {
      if (!validateResourceSelection()) return
      const rows = parseSiteBatchCreateRows(batchData)
      const normalizedTargetScope = platform ? normalizeUUID(targetScope) : null
      const normalizedOwnerUser = platform ? normalizeUUID(ownerUser) : null
      const normalizedHTTPPorts = normalizePortList(httpPorts)
      const normalizedHTTPSPorts = normalizePortList(httpsEnabled ? httpsPorts : '')
      const normalizedGroupID = groupID.trim() === '' ? null : normalizeUUID(groupID)
      const normalizedGroupName = groupName.trim()
      const groupInvalid = Boolean(groupID.trim() || normalizedGroupName) &&
        (!normalizedGroupID || normalizedGroupName.length === 0 || normalizedGroupName.length > 128)
      const portCollision = Boolean(normalizedHTTPPorts && normalizedHTTPSPorts &&
        normalizedHTTPPorts.some((port) => normalizedHTTPSPorts.includes(port)))
      const normalizedCNAME = cname.trim() === '' ? '' : normalizeSiteDomain(cname, false)
      const cnameInvalid = normalizedCNAME === null
      setOwnerUserInvalid(platform && !normalizedOwnerUser)
      setBatchInvalid(!rows)
      if (!rows || (platform && (!normalizedTargetScope || !normalizedOwnerUser))) return
      if (!normalizedHTTPPorts || !normalizedHTTPSPorts || portCollision) {
        setFormError(t('validation.ports'))
        return
      }
      if (groupInvalid) {
        setFormError(t('validation.references'))
        return
      }
      if (cnameInvalid) {
        setFormError(t('validation.cname'))
        return
      }
      const forwarding = originForwarding()
      if (!forwarding) return
      const attempts: SiteCreateAttempt[] = []
      for (const row of rows) {
        const normalizedDomains = canonicalSiteDomains(row.domain.split(/[\n,]+/u))
        const originValues = row.origin.split(/[\n,]+/u).map((value) => value.trim()).filter(Boolean)
        const originCandidates = originValues.map(normalizeOrigin)
        const normalizedOrigins = originValues.length >= 1 && originValues.length <= 32 &&
          originCandidates.every((value) => value !== null) &&
          new Set(originCandidates).size === originCandidates.length
          ? originCandidates as string[]
          : null
        const poolOrigins = normalizedOrigins?.map(originPoolOrigin) ?? []
        if (!normalizedDomains || !normalizedOrigins || poolOrigins.some((value) => value === null)) {
          setBatchInvalid(true)
          return
        }
        const input: CreateSiteRequest = {
          ...(platform ? { target_scope_id: normalizedTargetScope!, owner_id: normalizedOwnerUser! } : {}),
          basic: {
            // 社区版：站点不绑定套餐，套餐字段固定为空。
            package_id: null,
            package_subscription_id: null,
            cname_mode: '',
            cname_domain: '',
            cname_hostname: '',
            package_name: null,
            group_id: normalizedGroupID,
            group_name: normalizedGroupID ? normalizedGroupName : null,
            domains: normalizedDomains,
            http_enabled: true,
            ...(normalizedHTTPPorts.length > 0 ? { http_listen_ports: normalizedHTTPPorts } : {}),
            ...(httpsEnabled && normalizedHTTPSPorts.length === 0 ? {} : { https_listen_ports: normalizedHTTPSPorts }),
            origins: normalizedOrigins,
            cname: normalizedCNAME!,
            https_enabled: httpsEnabled,
            enabled: true,
            status: 'active',
            is_default: false,
          },
          origin_pool: {
            origins: poolOrigins as SiteOrigin[],
            ...(balanceMethod ? { balance_method: balanceMethod } : {}),
            failover_tries: 1,
            // 回源超时暂仍发送系统默认：服务端在没有用户默认时不补超时（normalizeOriginPool 要求 ≥50ms），
            // 省略会 400。服务端兜底（CU-SITE-02 服务端部分）合入后再改为省略。
            connect_timeout_ms: 3000,
            read_timeout_ms: 30000,
            ...forwarding,
          },
          ...(canAutoDNS && dnsProviderID ? { dns_provider_id: dnsProviderID } : {}),
        }
        attempts.push({ input, key: writeKey('create-batch'), body: JSON.stringify(input), owner, ownerKey })
      }
      frozen = attempts
    }
    if (!persistSiteCreateRetry(retryStorageKey, frozen.map(({ input, key, body }) => ({ input, key, body })))) {
      setFormError(t('batch.storageFailed'))
      return
    }
    inFlightBatchAttempt.current = frozen
    setFormError(null)
    setError(null)
    batchMutation.mutate(frozen)
  }

  const submit = () => {
    if (storageBlocked) return
    if (mode === 'batch') {
      submitBatch()
      return
    }
    if (inFlightAttempt.current || !sessionAccess('sites.manage')) return
    let frozen = attempt
    if (!frozen) {
      if (!validateResourceSelection()) return
      const normalizedTargetScope = platform ? normalizeUUID(targetScope) : null
      const normalizedOwnerUser = platform ? normalizeUUID(ownerUser) : null
      const normalizedDomains = canonicalSiteDomains(domain.split(/[\n,]+/u))
      const originValues = origin.split(/[\n,]+/u).map((value) => value.trim()).filter(Boolean)
      const originCandidates = originValues.map(normalizeOrigin)
      const normalizedOrigins = originValues.length >= 1 && originValues.length <= 32 &&
        originCandidates.every((value) => value !== null) &&
        new Set(originCandidates).size === originCandidates.length
        ? originCandidates as string[]
        : null
      const poolOrigins = normalizedOrigins?.map(originPoolOrigin) ?? []
      const normalizedHTTPPorts = normalizePortList(httpPorts)
      const normalizedHTTPSPorts = normalizePortList(httpsEnabled ? httpsPorts : '')
      const portCollision = Boolean(normalizedHTTPPorts && normalizedHTTPSPorts &&
        normalizedHTTPPorts.some((port) => normalizedHTTPSPorts.includes(port)))
      const normalizedGroupID = groupID.trim() === '' ? null : normalizeUUID(groupID)
      const normalizedGroupName = groupName.trim()
      const groupInvalid = Boolean(groupID.trim() || normalizedGroupName) &&
        (!normalizedGroupID || normalizedGroupName.length === 0 || normalizedGroupName.length > 128)
      const normalizedCNAME = cname.trim() === '' ? '' : normalizeSiteDomain(cname, false)
      const cnameInvalid = normalizedCNAME === null
      setOwnerUserInvalid(platform && !normalizedOwnerUser)
      setDomainInvalid(!normalizedDomains)
      setOriginInvalid(!normalizedOrigins || poolOrigins.some((value) => value === null))
      if ((platform && (!normalizedTargetScope || !normalizedOwnerUser)) || !normalizedDomains ||
        !normalizedOrigins || poolOrigins.some((value) => value === null)) return
      if (!normalizedHTTPPorts || !normalizedHTTPSPorts || portCollision) {
        setFormError(t('validation.ports'))
        return
      }
      if (groupInvalid) {
        setFormError(t('validation.references'))
        return
      }
      if (cnameInvalid) {
        setFormError(t('validation.cname'))
        return
      }
      const forwarding = originForwarding()
      if (!forwarding) return

      const input: CreateSiteRequest = {
        ...(platform
          ? { target_scope_id: normalizedTargetScope!, owner_id: normalizedOwnerUser! }
          : {}),
        basic: {
          // 社区版：站点不绑定套餐，套餐字段固定为空。
          package_id: null,
          package_subscription_id: null,
          cname_mode: '',
          cname_domain: '',
          cname_hostname: '',
          package_name: null,
          group_id: normalizedGroupID,
          group_name: normalizedGroupID ? normalizedGroupName : null,
          domains: normalizedDomains,
          http_enabled: true,
          ...(normalizedHTTPPorts.length > 0 ? { http_listen_ports: normalizedHTTPPorts } : {}),
          ...(httpsEnabled && normalizedHTTPSPorts.length === 0 ? {} : { https_listen_ports: normalizedHTTPSPorts }),
          origins: normalizedOrigins,
          cname: normalizedCNAME!,
          https_enabled: httpsEnabled,
          enabled: true,
          status: 'active',
          is_default: false,
        },
        origin_pool: {
          origins: poolOrigins as SiteOrigin[],
          ...(balanceMethod ? { balance_method: balanceMethod } : {}),
          failover_tries: 1,
          // 见批量建站同处：服务端兜底合入前仍发送系统默认超时。
          connect_timeout_ms: 3000,
          read_timeout_ms: 30000,
          ...forwarding,
        },
        ...(canAutoDNS && dnsProviderID ? { dns_provider_id: dnsProviderID } : {}),
      }
      frozen = { input, key: writeKey('create'), body: JSON.stringify(input), owner, ownerKey }
    }
    inFlightAttempt.current = frozen
    setError(null)
    mutation.mutate(frozen)
  }
  const uncertain = batchUncertain || Boolean(attempt && error && writeOutcomeUnknown(error))
  const busy = mutation.isPending || batchMutation.isPending
  const formLocked = busy || batchUncertain || storageBlocked
  const batchReady = batchData.trim() !== '' && !batchInvalid

  return (
    <Modal
      className="site-action-modal site-create-modal"
      title={t('title')}
      open
      width={620}
      confirmLoading={busy}
      okText={attempt || batchUncertain ? t('actions.retrySameRequest') : mode === 'batch' ? t('actions.confirm') : t('actions.create')}
      cancelText={t('actions.cancel')}
      okButtonProps={{ disabled: busy || storageBlocked || (mode === 'single' ? domain.trim() === '' || origin.trim() === '' : !batchReady) }}
      cancelButtonProps={{ disabled: formLocked }}
      closable={!formLocked}
      maskClosable={!formLocked}
      keyboard={!formLocked}
      onCancel={onClose}
      onOk={submit}
    >
      {storageBlocked ? <Alert className="site-modal-notice" showIcon type="error" message={t('batch.storageBlocked')} /> : null}
      {error || batchUncertain ? (
        <Alert
          className="site-modal-notice"
          showIcon
          type={uncertain ? 'warning' : 'error'}
          message={uncertain ? t('resultUnknown') : createErrorMessage(error!.code, t, error!.field)}
          description={batchUncertain ? t('batch.resultUnknownHelp') : uncertain ? t('resultUnknownDescription') : undefined}
        />
      ) : null}
      {formError ? <Alert className="site-modal-notice" showIcon type="error" message={formError} /> : null}
      {error?.code === 'domain_ownership_required' && !platform && mode === 'single' ? (
        <div className="site-modal-notice">
          <DomainOwnershipPanel domain={ownershipDomain(domain)} onVerified={() => setError(null)} />
        </div>
      ) : null}
      {batchResult && batchResult.failed.length > 0 ? (
        <Alert
          className="site-modal-notice"
          showIcon
          type="warning"
          message={t('batch.partialResult', { failed: batchResult.failed.length, saved: batchResult.saved.length })}
        />
      ) : null}
      <div className="site-create-form">
        <div className="site-create-tabs" role="tablist" aria-label={t('tabs.label')}>
          {(['single', 'batch'] as const).map((value) => (
            <button
              key={value}
              className={mode === value ? 'is-active' : undefined}
              type="button"
              role="tab"
              disabled={formLocked}
              aria-selected={mode === value}
              onClick={() => {
                if (formLocked) return
                setMode(value)
                setError(null)
                setFormError(null)
                setBatchInvalid(false)
                setBatchResult(null)
              }}
            >
              {t(`tabs.${value}`)}
            </button>
          ))}
        </div>
        {platform ? (
            <AdvancedField label={t('ownerUser.label')}>
              <Select
                aria-label={t('ownerUser.ariaLabel')}
                showSearch
                filterOption={false}
                labelInValue
                value={selectedUser ? { value: selectedUser.id, label: `${selectedUser.username}（${selectedUser.display_id}）` } : undefined}
                status={ownerUserInvalid ? 'error' : undefined}
                placeholder={t('ownerUser.searchPlaceholder')}
                disabled={formLocked || !canReadUsers}
                loading={users.isFetching}
                options={userOptions.map((item) => ({ value: item.id, label: `${item.username}（${item.display_id}）` }))}
                onSearch={setUserSearch}
                onChange={(value) => changeOwnerUser(value.value)}
                notFoundContent={users.isFetching ? <Spin size="small" /> : t('lookup.empty')}
                popupRender={(menu) => <>{menu}{users.hasNextPage ? <Button block loading={users.isFetchingNextPage} onClick={() => void users.fetchNextPage()}>{t('lookup.more')}</Button> : null}</>}
              />
              {ownerUserInvalid ? <small>{t('ownerUser.invalid')}</small> : null}
              {!canReadUsers ? <small>{t('lookup.usersDenied')}</small> : null}
              {users.isError ? <small role="alert">{t('lookup.failed')} <Button size="small" onClick={() => void users.refetch()}>{t('lookup.retry')}</Button></small> : null}
            </AdvancedField>
        ) : null}
        {mode === 'single' ? (
          <>
            <AdvancedField label={t('domain.label')}>
              <Input.TextArea
                aria-label={t('domain.label')}
                value={domain}
                status={domainInvalid ? 'error' : undefined}
                placeholder={t('domain.placeholder')}
                disabled={formLocked}
                autoSize={{ minRows: 1, maxRows: 6 }}
                onChange={(event) => changeDomain(event.target.value)}
              />
              {domainInvalid ? <small>{t('domain.invalid')}</small> : null}
              <small className="site-create-help">{t('domain.help')}</small>
            </AdvancedField>
            <AdvancedField label={t('origin.label')}>
              <Input.TextArea
                aria-label={t('origin.label')}
                value={origin}
                status={originInvalid ? 'error' : undefined}
                placeholder={t('origin.placeholder')}
                disabled={formLocked}
                autoSize={{ minRows: 1, maxRows: 6 }}
                onChange={(event) => changeOrigin(event.target.value)}
              />
              {originInvalid ? <small>{t('origin.invalid')}</small> : null}
              <small className="site-create-help">{t('origin.help')}</small>
            </AdvancedField>
          </>
        ) : (
          <>
            <AdvancedField label={t('batch.dataLabel')}>
              <Input.TextArea
                aria-label={t('batch.dataLabel')}
                value={batchData}
                status={batchInvalid ? 'error' : undefined}
                placeholder={t('batch.placeholder')}
                disabled={formLocked}
                rows={5}
                onChange={(event) => {
                  setBatchData(event.target.value)
                  setBatchInvalid(false)
                  setBatchResult(null)
                  setFormError(null)
                  setError(null)
                  setBatchAttempt(null)
                }}
              />
              {batchInvalid ? <small>{t('batch.invalid')}</small> : null}
              <small className="site-create-help">{t('batch.help')}</small>
            </AdvancedField>
            <AdvancedField label={t('batch.ignoreLabel')}>
              <Switch
                aria-label={t('batch.ignoreLabel')}
                checked={batchIgnoreErrors}
                disabled={formLocked}
                onChange={(checked) => setBatchIgnoreErrors(checked)}
              />
              <small className="site-create-help">{t('batch.ignoreHelp')}</small>
            </AdvancedField>
          </>
        )}
        <button
          className="site-create-advanced-toggle"
          type="button"
          aria-expanded={advancedOpen}
          disabled={formLocked}
          onClick={() => setAdvancedOpen((open) => !open)}
        >
          <span aria-hidden="true" />
          {advancedOpen ? t('advanced.collapse') : t('advanced.expand')}
          <ChevronDown className={advancedOpen ? 'is-open' : undefined} size={14} aria-hidden="true" />
          <span aria-hidden="true" />
        </button>
        {advancedOpen ? (
          <div className="site-create-advanced-fields">
            {/* C09: grouped as origin → listening/HTTPS → CNAME → group and DNS; how nodes reach
                the origin is an expert choice (defaults: HTTP, visitor Host). */}
            <AdvancedField label={t('originScheme.label')}>
              <Select
                aria-label={t('originScheme.label')}
                value={originScheme}
                disabled={formLocked}
                options={(['http', 'https', 'follow'] as OriginScheme[]).map((value) => ({ value, label: t(`originScheme.options.${value}`) }))}
                allowClear placeholder={t('originScheme.defaultPlaceholder')}
                onChange={(value?: OriginScheme) => changeAdditional(() => setOriginScheme(value))}
              />
              <small className="site-create-help">{t('originScheme.help')}</small>
            </AdvancedField>
            <AdvancedField label={t('originHost.label')}>
              <Input
                aria-label={t('originHost.label')}
                value={originHost}
                status={originHostInvalid ? 'error' : undefined}
                placeholder={t('originHost.placeholder')}
                disabled={formLocked}
                onChange={(event) => changeAdditional(() => { setOriginHost(event.target.value); setOriginHostInvalid(false) })}
              />
              {originHostInvalid ? <small>{t('originHost.invalid')}</small> : null}
              <small className="site-create-help">{t('originHost.help')}</small>
            </AdvancedField>
            <AdvancedField label={t('balance.label')}>
              <Select
                aria-label={t('balance.label')}
                value={balanceMethod}
                disabled={formLocked}
                options={(['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'] as OriginBalanceMethod[])
                  .map((value) => ({ value, label: t(`balance.options.${value}`) }))}
                allowClear placeholder={t('balance.defaultPlaceholder')}
                onChange={(value?: OriginBalanceMethod) => changeAdditional(() => setBalanceMethod(value))}
              />
            </AdvancedField>
            <AdvancedField label={t('httpPorts.label')}>
              <Input aria-label={t('httpPorts.label')} value={httpPorts} placeholder={t('httpPorts.placeholder')}
                disabled={formLocked} onChange={(event) => changeAdditional(() => setHTTPPorts(event.target.value))} />
            </AdvancedField>
            <AdvancedField label={t('httpsEnabled.label')}>
              <Switch aria-label={t('httpsEnabled.label')} checked={httpsEnabled} disabled={formLocked}
                onChange={(checked) => changeAdditional(() => setHTTPSEnabled(checked))} />
            </AdvancedField>
            <AdvancedField label={t('httpsPorts.label')}>
              <Input aria-label={t('httpsPorts.label')} value={httpsPorts} placeholder={t('httpsPorts.placeholder')}
                disabled={formLocked || !httpsEnabled} onChange={(event) => changeAdditional(() => setHTTPSPorts(event.target.value))} />
            </AdvancedField>
            <AdvancedField label={t('cname.label')}>
              <Input aria-label={t('cname.label')} value={cname} placeholder={t('cname.placeholder')}
                disabled={formLocked} onChange={(event) => changeAdditional(() => setCNAME(event.target.value))} />
              <small className="site-create-help">{t('cname.help')}</small>
            </AdvancedField>
            <AdvancedField label={t('groupSelect.label')}>
              <Select aria-label={t('groupSelect.label')} value={groupID || undefined}
                allowClear showSearch optionFilterProp="label" placeholder={t('groupSelect.placeholder')}
                disabled={formLocked || !targetScope} loading={groups.isFetching}
                options={groupOptions.map((item) => ({ value: item.id, label: item.name }))}
                notFoundContent={groups.isFetching ? <Spin size="small" /> : t('lookup.empty')}
                popupRender={(menu) => <>{menu}{groups.hasNextPage ? <Button block loading={groups.isFetchingNextPage} onClick={() => void groups.fetchNextPage()}>{t('lookup.more')}</Button> : null}</>}
                onChange={(value) => changeAdditional(() => {
                  const item = groupOptions.find((option) => option.id === value)
                  setGroupID(item?.id ?? '')
                  setGroupName(item?.name ?? '')
                })} />
              {groups.isError ? <small role="alert">{t('lookup.failed')} <Button size="small" onClick={() => void groups.refetch()}>{t('lookup.retry')}</Button></small> : null}
            </AdvancedField>
            {canAutoDNS ? (
              <AdvancedField label={tTabs('create.dnsApi')}>
                <Select aria-label={tTabs('create.dnsApi')} value={dnsProviderID || undefined} allowClear
                  placeholder={tTabs('create.dnsApiPlaceholder')} disabled={formLocked} loading={dnsProviders.isFetching}
                  options={verifiedDNSProviders.map((item) => ({ value: item.id, label: item.name }))}
                  notFoundContent={dnsProviders.isFetching ? <Spin size="small" /> : tTabs('create.dnsApiEmpty')}
                  onChange={(value?: string) => changeAdditional(() => setDNSProviderID(value ?? ''))} />
                {dnsProviders.isError ? <small role="alert">{tTabs('create.dnsApiFailed')} <Button size="small" onClick={() => void dnsProviders.refetch()}>{t('lookup.retry')}</Button></small> : null}
                <small className="site-create-help">{tTabs('create.dnsApiHelp')}</small>
              </AdvancedField>
            ) : null}
            <Alert showIcon type="info" message={t('tls.safeOnly')} description={t('defaults')} />
          </div>
        ) : null}
      </div>
    </Modal>
  )
}

function SiteLockModal({
  state,
  pending,
  onCancel,
  onReasonChange,
  onReload,
  onSubmit,
}: {
  state: LockDialogState | null
  pending: boolean
  onCancel: () => void
  onReasonChange: (reason: string) => void
  onReload: () => void
  onSubmit: () => void
}) {
  const { t, i18n } = useTranslation('sites')
  if (!state) return null

  const uncertain = Boolean(state.attempt && state.error && writeOutcomeUnknown(state.error))
  const isLock = state.action === 'lock'
  const reason = state.reason.trim()
  const invalidReason = isLock && (reason.length === 0 || reason.length > 500)
  const detailReady = Boolean(state.detail && lockActionMatches(state.action, state.detail))
  const canSubmit =
    detailReady &&
    !state.loading &&
    !pending &&
    !state.reloadRequired &&
    !state.stateMismatch &&
    !invalidReason
  const lock = state.detail?.lock

  let displayedError = state.error ? errorCodeMessage(state.error.code, t) : ''
  if (uncertain) displayedError = t('lock.outcomeUnknown')
  else if (state.error?.code === 'version_conflict') displayedError = t('lock.versionChanged')
  else if (state.stateMismatch) displayedError = t('lock.stateChanged')

  return (
    <Modal
      className="site-action-modal site-lock-modal"
      title={isLock ? t('lock.lockTitle') : t('lock.unlockTitle')}
      open
      width={520}
      confirmLoading={pending}
      okText={uncertain ? t('actions.retrySameRequest') : isLock ? t('actions.confirmLock') : t('actions.confirmUnlock')}
      cancelText={t('actions.cancel')}
      okButtonProps={{ disabled: uncertain ? pending : !canSubmit, danger: isLock }}
      cancelButtonProps={{ disabled: pending || uncertain }}
      closable={!pending && !uncertain}
      maskClosable={!pending && !uncertain}
      keyboard={!pending && !uncertain}
      onCancel={onCancel}
      onOk={onSubmit}
    >
      <p className="site-lock-target">{state.item.domain}</p>
      <Alert className="site-lock-impact" type={isLock ? 'warning' : 'info'} showIcon message={isLock ? t('lock.lockImpact') : t('lock.unlockImpact')} />
      {state.loading ? (
        <div className="site-lock-loading" aria-label={t('lock.loading')}>
          <Spin size="small" />
        </div>
      ) : null}
      {state.error ? (
        <Alert
          className="site-lock-alert"
          showIcon
          type={uncertain ? 'warning' : 'error'}
          message={displayedError}
          description={
            uncertain
              ? t('lock.retryDescription')
              : state.stateMismatch
                ? t('lock.closeForLatest')
                : state.reloadRequired
                  ? t('lock.reloadRequired')
                  : undefined
          }
          action={
            state.reloadRequired ? (
              <Button size="small" onClick={onReload}>
                {t('actions.reloadState')}
              </Button>
            ) : state.stateMismatch ? (
              <Button size="small" onClick={onCancel}>
                {t('actions.close')}
              </Button>
            ) : undefined
          }
        />
      ) : null}
      {state.detail && isLock ? (
        <label className="site-lock-reason-field">
          <span>{t('lock.reason')}</span>
          <Input.TextArea
            aria-label={t('lock.reason')}
            value={state.reason}
            rows={4}
            maxLength={500}
            showCount
            disabled={pending || uncertain || state.reloadRequired || state.stateMismatch}
            placeholder={t('lock.reasonPlaceholder')}
            onChange={(event) => onReasonChange(event.target.value)}
          />
        </label>
      ) : null}
      {state.detail && !isLock && lock?.locked ? (
        <div className="site-unlock-summary">
          <span>{t('lock.currentReason')}</span>
          <strong>{lock.reason ?? t('values.placeholder')}</strong>
          <small>
            {[lock.operator?.display_name, lock.locked_at ? displayDate(lock.locked_at, i18n.resolvedLanguage ?? i18n.language, t('values.placeholder')) : null]
              .filter(Boolean)
              .join(' · ') || t('values.placeholder')}
          </small>
        </div>
      ) : null}
    </Modal>
  )
}

function SiteStatusModal({
  state,
  pending,
  canLock,
  onCancel,
  onStatusChange,
  onSubmit,
}: {
  state: SiteStatusDialogState | null
  pending: boolean
  canLock: boolean
  onCancel: () => void
  onStatusChange: (status: SiteOperationalStatus) => void
  onSubmit: () => void
}) {
  const { t } = useTranslation('sites')
  if (!state) return null

  const attempt = state.attempt
  const options: Array<{ value: SiteOperationalStatus; label: string; disabled?: boolean }> = [
    { value: 'normal', label: t('states.active') },
    { value: 'locked', label: t('states.locked'), disabled: !canLock },
    { value: 'traffic_exceeded', label: t('states.traffic_exceeded') },
    { value: 'package_expired', label: t('states.package_expired') },
  ]
  const canSubmit = !pending && (attempt.status !== 'locked' || canLock)

  return (
    <Modal
      className="site-action-modal site-status-modal"
      title={t('status.title')}
      open
      confirmLoading={pending}
      okText={t('actions.confirm')}
      cancelText={t('actions.cancel')}
      okButtonProps={{ disabled: !canSubmit }}
      cancelButtonProps={{ disabled: pending }}
      closable={!pending}
      maskClosable={!pending}
      keyboard={!pending}
      onCancel={onCancel}
      onOk={onSubmit}
    >
      <p>{t('status.description', { count: attempt.targets.length })}</p>
      <Select
        aria-label={t('status.label')}
        value={attempt.status}
        options={options}
        disabled={pending}
        onChange={onStatusChange}
      />
      {!canLock ? <p className="site-status-hint">{t('status.lockUnavailable')}</p> : null}
      {state.error ? (
        <Alert
          className="site-lock-alert"
          showIcon
          type={writeOutcomeUnknown(state.error) ? 'warning' : 'error'}
          message={writeOutcomeUnknown(state.error) ? t('status.outcomeUnknown') : errorCodeMessage(state.error.code, t)}
        />
      ) : null}
      <ul className="site-status-targets">
        {attempt.targets.map((target) => <li key={target.id}>{target.domain}</li>)}
      </ul>
    </Modal>
  )
}

function SiteListPageSession({
  principal,
  owner,
  ownerKey,
  role,
}: {
  principal: Principal
  owner: SiteSessionOwner
  ownerKey: string
  role: 'admin' | 'user'
}) {
  const { t, i18n } = useTranslation('sites')
  const { t: tCreate } = useTranslation('siteCreate')
  const { t: tCname, i18n: i18nInstance } = useTranslation('siteCnameRegeneration')
  const { t: tExport } = useTranslation('siteDomainExport')
  const { t: tDomain } = useTranslation('domainTrust')
  const { t: tQuick } = useTranslation('siteHttpsQuick')
  const [httpsQuickSite, setHttpsQuickSite] = useState<SiteListItem | null>(null)
  const [transferSite, setTransferSite] = useState<SiteListItem | null>(null)
  const { t: tTransfer } = useTranslation('siteTransfer')
  const { message } = App.useApp()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const sessionAccessToken = useSessionStore((state) => state.accessToken)
  const cacheControlOff = useRuntimeFeatureOff('cache_control', sessionAccessToken)
  const ownerRef = useRef({ ownerKey, owner })
  const queryOwner = ownerRef.current.owner
  const lineageActiveRef = useRef(true)
  const retryStorageKey = `${siteBatchRetryStorageKey(queryOwner[0], queryOwner[1])}:${
    encodeURIComponent(queryOwner[2] ?? 'null')
  }:${encodeURIComponent(queryOwner[3])}`
  const [page, setPage] = useState(1)
  const routeState = useLocation().state as { siteSubnav?: unknown; dnsCheckBack?: SiteDnsCheckContext['back'] } | null
  const [activeSubnav, setActiveSubnav] = useState<'list' | 'groups' | 'defaults' | 'dnsApi' | 'dnsCheck'>(
    routeState?.siteSubnav === 'groups' || routeState?.siteSubnav === 'dnsApi' || routeState?.siteSubnav === 'defaults' ||
      routeState?.siteSubnav === 'dnsCheck' ? routeState.siteSubnav : 'list')
  const [limit, setLimit] = useState(10)
  // 快速搜索可从分享链接带入（?field=&q=），已生效后写回 URL。
  const [initialParams] = useSearchParams()
  const initialQuick = filterParam(initialParams, 'q')
  const initialField = (filterParam(initialParams, 'field') || 'domain') as SiteQuickField
  const [filters, setFilters] = useState<SiteFilters>(() => initialQuick ? { [initialField]: initialQuick } : {})
  const [advancedDraft, setAdvancedDraft] = useState<SiteFilters>({})
  const [quickField, setQuickField] = useState<SiteQuickField>(initialField)
  const [quickValue, setQuickValue] = useState(initialQuick)
  const [appliedAdvanced, setAppliedAdvanced] = useState<SiteFilters>({})
  const [appliedQuickField, setAppliedQuickField] = useState<SiteQuickField | null>(initialQuick ? initialField : null)
  const [selectedKeys, setSelectedKeys] = useState<React.Key[]>([])
  const [dialog, setDialog] = useState<Dialog>(null)
  const [unsupportedNotice, setUnsupportedNotice] = useState<string | null>(null)
  const [operationNotice, setOperationNotice] = useState<SiteOperationNotice | null>(null)
  const [exportPending, setExportPending] = useState(false)
  const [exportNotice, setExportNotice] = useState<SiteExportNotice | null>(null)
  // Platform exports must name the target tenant; picked in a dialog before exporting.
  const [exportTargetOpen, setExportTargetOpen] = useState(false)
  const [exportTargetScope, setExportTargetScope] = useState('')
  const [lockDialog, setLockDialog] = useState<LockDialogState | null>(null)
  const [statusDialog, setStatusDialog] = useState<SiteStatusDialogState | null>(null)
  const [batchAttempt, setBatchAttempt] = useState<SiteBatchAttempt | null>(null)
  const [batchResults, setBatchResults] = useState<BatchResultState | null>(null)
  const [batchError, setBatchError] = useState<ApiError | null>(null)
  const [terminalForbidden, setTerminalForbidden] = useState(false)
  const [batchRetryLock, setBatchRetryLock] = useState<SiteBatchRetryLockState>(() =>
    restoreSiteBatchRetry(retryStorageKey),
  )
  const subnavRef = useRef<HTMLDivElement>(null)
  const retryStorageChanged = batchRetryLock.storageKey !== retryStorageKey
  const retryAttempt = retryStorageChanged ? null : batchRetryLock.attempt
  const retryCorrupted = retryStorageChanged || batchRetryLock.corrupted
  const retryPersistenceFailed = !retryStorageChanged && batchRetryLock.persistenceFailed
  const canManageSites = sitePrincipalCan(principal, 'sites.manage')
  const canRequestCertificate = principal.scope_kind === 'tenant' && principal.permissions.includes('certificates.manage')
  const canExportSites = sitePrincipalCan(principal, 'sites.export')
  const canRegenerateCname = canManageSites && sitePrincipalCan(principal, 'dns.manage')
  const canManageLock = role === 'admin' && canManageSites
  // 更换所属用户：平台管理员（服务端按 tenantaccess 平台管理员规则再校验）。
  const canTransferSite = role === 'admin' && principal.scope_kind === 'platform' && canManageSites
  const canReadDNSReconcile = principal.scope_kind === 'tenant' && principal.permissions.includes('dns.read')
  // DNS API：租户看自己的 DNS 服务商账号（本页内嵌，不跳管理员 /node/dns）；平台管理员仍去节点管理 > DNS配置。
  const canOpenDnsApi = principal.permissions.includes('dns.read') &&
    (principal.scope_kind === 'tenant' || (role === 'admin' && principal.scope_kind === 'platform'))
  // 默认设置：租户在本页管理自己新建网站的默认值（/v1/site-defaults）；平台管理员仍去 系统设置 > 网站默认。
  const tenantScope = principal.scope_kind === 'tenant'
  const canOpenWebsiteDefaults = tenantScope ? principal.permissions.includes('sites.read')
    : role === 'admin' && principal.scope_kind === 'platform' && principal.permissions.includes('system_configuration.read')
  const canSelectSites = canManageSites || canReadDNSReconcile || canRequestCertificate
  const language = i18n.resolvedLanguage ?? i18n.language
  const triStateOptions = [
    { value: '', label: t('states.any') },
    { value: 'true', label: t('states.yes') },
    { value: 'false', label: t('states.no') },
  ]
  const statusOptions = [
    { value: '', label: t('states.any') },
    ...(Object.keys(siteStatus) as Array<SiteStatus | 'normal'>).map((value) => ({
      value,
      label: t(`states.${value === 'normal' ? 'active' : value}`),
    })),
  ]
  const quickFieldOptions: Array<{ value: SiteQuickField; label: string }> = role === 'admin'
    ? [
        { value: 'domain', label: t('search.domain') },
        { value: 'domains', label: t('search.domains') },
        { value: 'origin_ip', label: t('search.originIp') },
        { value: 'site_ids', label: t('search.siteIds') },
        { value: 'owner', label: t('search.ownerId') },
        { value: 'region_id', label: t('search.region') },
        { value: 'node_group_id', label: t('search.nodeGroup') },
        { value: 'cname_domain', label: t('search.cnameDomain') },
        { value: 'cname_hostname', label: t('search.cnameHostname') },
        { value: 'http_port', label: t('search.httpPort') },
        { value: 'https_port', label: t('search.httpsPort') },
        { value: 'https_enabled', label: t('search.httpsEnabled') },
        { value: 'enabled', label: t('search.siteEnabled') },
        { value: 'is_default', label: t('search.defaultSite') },
        { value: 'sync_status', label: t('search.syncStatus') },
        { value: 'status', label: t('search.siteStatus') },
      ]
    : [
        { value: 'domain', label: t('search.domain') },
        { value: 'origin_ip', label: t('search.originIp') },
        { value: 'site_ids', label: t('search.siteIds') },
      ]

  useEffect(() => {
    if (!retryStorageChanged) return
    setBatchRetryLock(restoreSiteBatchRetry(retryStorageKey))
  }, [retryStorageChanged, retryStorageKey])

  const currentSessionAccess = useCallback((permission: SitePermission) => (
    lineageActiveRef.current ? currentSiteSessionAccess(ownerKey, permission) : null
  ), [ownerKey])
  const currentBatchSessionAccess = useCallback((action: BatchSiteAction) => {
    const token = currentSessionAccess('sites.manage')
    if (!token || (action === 'regenerate_cname' && !currentSessionAccess('dns.manage'))) return null
    return token
  }, [currentSessionAccess])
  const queryPrefix = useMemo(() => ['sites', queryOwner] as const, [queryOwner])
  const queryKey = useMemo(
    () => terminalForbidden
      ? ['sites-terminal', queryOwner] as const
      : [...queryPrefix, role, page, limit, filters] as const,
    [filters, limit, page, queryOwner, queryPrefix, role, terminalForbidden],
  )
  const queryIdentity = JSON.stringify(queryKey)
  const activeQueryIdentityRef = useRef(queryIdentity)
  activeQueryIdentityRef.current = queryIdentity
  const exportIdentity = JSON.stringify([ownerKey, filters])
  const activeExportIdentityRef = useRef(exportIdentity)
  activeExportIdentityRef.current = exportIdentity

  const removeOwnerCache = useCallback(() => {
    queryClient.removeQueries({ queryKey: queryPrefix })
    // 点「管理」跳转时，编辑页已在同一次提交里挂上了 ['site-detail', owner, id]；
    // 删掉它会静默取消请求，编辑页永远停在加载中。只删没人观察的站点详情缓存。
    const queryCache = queryClient.getQueryCache()
    for (const detailQuery of queryCache.findAll({ queryKey: ['site-detail', queryOwner] })) {
      if (detailQuery.getObserversCount() === 0) queryCache.remove(detailQuery)
    }
    for (const key of ['site-create-users', 'site-create-groups']) {
      queryClient.removeQueries({ queryKey: [key, queryOwner] })
    }
    const mutationCache = queryClient.getMutationCache()
    for (const mutationKey of [
      ['site-create', queryOwner],
      ['site-batch-create', queryOwner],
      ['site-lock', queryOwner],
      ['site-batch', queryOwner],
    ] as const) {
      for (const mutation of mutationCache.findAll({ mutationKey, exact: true })) {
        mutationCache.remove(mutation)
      }
    }
  }, [queryClient, queryOwner, queryPrefix])

  // N22: while a listed site's CNAME is pending, poll every 2 s for at most
  // 60 s so the address appears without a manual refresh; stop once none is.
  const cnamePendingSinceRef = useRef<number | null>(null)
  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentSessionAccess('sites.read')
      if (!token) throw staleSiteAttempt
      try {
        const result = await sitesApi.list(token, { page, limit, ...siteRequestFilters(filters) })
        if (!currentSessionAccess('sites.read') || activeQueryIdentityRef.current !== queryIdentity) {
          throw staleSiteAttempt
        }
        return result
      } catch (error) {
        if (!currentSessionAccess('sites.read') || activeQueryIdentityRef.current !== queryIdentity) {
          throw staleSiteAttempt
        }
        throw error
      }
    },
    enabled: !terminalForbidden && activeSubnav === 'list',
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
    refetchInterval: (current) => {
      const pending = current.state.data?.items.some((item) => item.cname_state === 'pending') ?? false
      if (!pending) {
        cnamePendingSinceRef.current = null
        return false
      }
      cnamePendingSinceRef.current ??= Date.now()
      return Date.now() - cnamePendingSinceRef.current < cnamePendingPollWindowMs ? cnamePendingPollIntervalMs : false
    },
  })

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!currentSiteSessionAccess(ownerKey, 'sites.read')) {
        removeOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) removeOwnerCache()
      })
    }
  }, [ownerKey, removeOwnerCache])

  const selectedItems = useMemo(() => {
    const keys = new Set(selectedKeys.map(String))
    return (query.data?.items ?? []).filter((item) => keys.has(item.id))
  }, [query.data?.items, selectedKeys])

  const clearPersistedBatchRetry = useCallback(() => {
    const cleared = clearSiteBatchRetry(retryStorageKey)
    setBatchRetryLock({
      storageKey: retryStorageKey,
      attempt: null,
      corrupted: !cleared,
      persistenceFailed: false,
    })
    return cleared
  }, [retryStorageKey])

  useEffect(() => {
    if (canRegenerateCname) return
    setBatchAttempt((current) => current?.action === 'regenerate_cname' ? null : current)
    setBatchResults((current) => current?.attempt.action === 'regenerate_cname' ? null : current)
    if (retryAttempt?.action === 'regenerate_cname') clearPersistedBatchRetry()
  }, [canRegenerateCname, clearPersistedBatchRetry, retryAttempt])

  const denyCurrentOwner = useCallback(() => {
    lineageActiveRef.current = false
    setTerminalForbidden(true)
    setSelectedKeys([])
    setDialog(null)
    setUnsupportedNotice(null)
    setOperationNotice(null)
    setLockDialog(null)
    setStatusDialog(null)
    setBatchAttempt(null)
    setBatchResults(null)
    setBatchError(null)
    clearSiteBatchRetry(retryStorageKey)
    setBatchRetryLock({
      storageKey: retryStorageKey,
      attempt: null,
      corrupted: false,
      persistenceFailed: false,
    })
    queueMicrotask(removeOwnerCache)
  }, [removeOwnerCache, retryStorageKey])

  useEffect(() => {
    if (terminalSiteAuthorizationError(query.error) && currentSessionAccess('sites.read')) {
      denyCurrentOwner()
    }
  }, [currentSessionAccess, denyCurrentOwner, query.error])

  const cacheSiteDetail = useCallback(
    (saved: SiteDetail, cacheOwner: SiteSessionOwner) => {
      queryClient.setQueryData(['site-detail', cacheOwner, saved.id], saved)
      queryClient.setQueriesData<SiteListResponse>({ queryKey: ['sites', cacheOwner] }, (current) => {
        if (!current) return current
        return {
          ...current,
          items: current.items.map((item) =>
            item.id === saved.id
              ? {
                  ...item,
                  version: saved.version,
                  status: saved.basic.status,
                  status_state: saved.status_state,
                  status_code: saved.status_code,
                  status_recovery: saved.status_recovery,
                  listener_state: saved.listener_state,
                  lock: saved.lock,
                }
              : item,
          ),
        }
      })
    },
    [queryClient],
  )

  const lockMutation = useMutation({
    mutationKey: ['site-lock', queryOwner],
    mutationFn: async (attempt: LockAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('sites.manage') : null
      if (!token) throw staleSiteAttempt
      try {
        const saved = await (attempt.action === 'lock'
          ? sitesApi.lock(token, attempt.id, attempt.input as LockSiteRequest, attempt.key)
          : sitesApi.unlock(token, attempt.id, attempt.input as UnlockSiteRequest, attempt.key))
        if (!currentSessionAccess('sites.read')) throw staleSiteAttempt
        return saved
      } catch (error) {
        if (!currentSessionAccess('sites.read')) throw staleSiteAttempt
        throw error
      }
    },
    onSuccess: (saved, attempt) => {
      if (!currentSessionAccess('sites.read')) return
      cacheSiteDetail(saved, attempt.owner)
      void queryClient.invalidateQueries({ queryKey: ['sites', attempt.owner] })
      setLockDialog(null)
      setOperationNotice({
        type: 'success',
        namespace: 'sites',
        key: attempt.action === 'lock'
          ? 'lock.successLocked'
          : saved.status_recovery?.trigger === 'unlock' &&
              (saved.status_recovery.task_state === 'queued' || saved.status_recovery.task_state === 'running')
            ? 'lock.successUnlockQueued'
            : 'lock.successUnlocked',
        domain: saved.basic.domains[0] || attempt.id,
      })
    },
    onError: (error: unknown, attempt) => {
      if (error === staleSiteAttempt || !currentSessionAccess('sites.read')) return
      const apiError =
        error instanceof ApiError ? error : new ApiError(t('errors.operationFailed'))
      if (terminalSiteAuthorizationError(apiError)) {
        denyCurrentOwner()
        return
      }
      const uncertain = writeOutcomeUnknown(error)
      setLockDialog((current) => {
        if (!current || current.item.id !== attempt.id) return current
        const reloadRequired =
          !uncertain &&
          (apiError.code === 'version_conflict' || apiError.code === 'site_lock_state_conflict')
        return {
          ...current,
          error: apiError,
          attempt: uncertain ? attempt : null,
          reloadRequired,
        }
      })
    },
  })

  const statusMutation = useMutation({
    mutationKey: ['site-status', queryOwner],
    mutationFn: async (attempt: SiteStatusAttempt) => {
      const token = attempt.ownerKey === ownerKey ? currentSessionAccess('sites.manage') : null
      if (!token) throw staleSiteAttempt
      const saved: SiteDetail[] = []
      try {
        for (const target of attempt.targets) {
          let detail = await sitesApi.detail(token, target.id)
          if (!detail) throw new ApiError(t('errors.site_not_found'), 404, 'site_not_found')
          const desiredStatus = attempt.status === 'normal' ? 'active' : attempt.status
          const alreadyDesired = attempt.status === 'locked'
            ? detail.lock.locked
            : !detail.lock.locked && detail.basic.enabled && detail.basic.status === desiredStatus
          if (alreadyDesired) {
            saved.push(detail)
            continue
          }
          if (detail.version !== target.version) {
            throw new ApiError(t('errors.version_conflict'), 409, 'version_conflict')
          }
          if (attempt.status === 'locked') {
            detail = await sitesApi.lock(
              token,
              target.id,
              { expected_version: detail.version, reason: attempt.reason },
              `${attempt.key}-${target.id}-lock`,
            )
          } else {
            if (detail.lock.locked) {
              detail = await sitesApi.unlock(
                token,
                target.id,
                { expected_version: detail.version },
                `${attempt.key}-${target.id}-unlock`,
              )
            }
            detail = await sitesApi.patchBasic(
              token,
              target.id,
              {
                expected_version: detail.version,
                section: 'basic',
                changes: { ...detail.basic, enabled: true, status: desiredStatus },
              },
              `${attempt.key}-${target.id}-status`,
            )
          }
          saved.push(detail)
        }
        if (!currentSessionAccess('sites.read')) throw staleSiteAttempt
        return saved
      } catch (error) {
        if (!currentSessionAccess('sites.read')) throw staleSiteAttempt
        throw error
      }
    },
    onSuccess: async (saved, attempt) => {
      if (!currentSessionAccess('sites.read')) return
      saved.forEach((item) => cacheSiteDetail(item, attempt.owner))
      setStatusDialog(null)
      setSelectedKeys([])
      setOperationNotice({
        type: 'success',
        namespace: 'sites',
        key: 'status.success',
        domain: saved[0]?.basic.domains[0] || attempt.targets[0]?.domain || attempt.targets[0]?.id || '',
        count: saved.length,
      })
      await queryClient.invalidateQueries({ queryKey: ['sites', attempt.owner] })
    },
    onError: (error: unknown) => {
      if (error === staleSiteAttempt || !currentSessionAccess('sites.read')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('errors.operationFailed'))
      if (terminalSiteAuthorizationError(apiError)) {
        denyCurrentOwner()
        return
      }
      setStatusDialog((current) => current ? { ...current, error: apiError } : current)
    },
  })

  const batchMutation = useMutation({
    mutationKey: ['site-batch', queryOwner],
    mutationFn: async ({ attempt, ownerKey: attemptOwnerKey }: SiteBatchWriteAttempt) => {
      const token = attemptOwnerKey === ownerKey
        ? currentBatchSessionAccess(attempt.action)
        : null
      if (!token) throw staleSiteAttempt
      try {
        const result = await sitesApi.batchAction(token, attempt.input, attempt.key, attempt.body)
        if (!currentBatchSessionAccess(attempt.action)) throw staleSiteAttempt
        return result
      } catch (error) {
        if (!currentBatchSessionAccess(attempt.action)) throw staleSiteAttempt
        // A 500 is the control API's own answer, so the batch
        // transaction has ended. It is all-or-nothing: if every target still
        // has the expected version nothing was written (a definite failure);
        // otherwise the same idempotency key returns the stored result.
        if (error instanceof ApiError && error.status === 500) {
          const settled = await settleBatchOutcome(token, attempt).catch(() => null)
          if (!currentBatchSessionAccess(attempt.action)) throw staleSiteAttempt
          if (settled === 'not_applied') {
            batchNotApplied.add(error)
          } else if (settled) {
            return settled
          }
        }
        throw error
      }
    },
    onSuccess: async (result, writeAttempt) => {
      const { attempt } = writeAttempt
      if (!currentBatchSessionAccess(attempt.action)) return
      const cleared = clearPersistedBatchRetry()
      setBatchError(
        cleared
          ? null
          : new ApiError(t('errors.retryRecordClearFailed'), 0, 'retry_lock_corrupted'),
      )
      setBatchAttempt(null)
      const singleItem = attempt.single && attempt.action === 'regenerate_cname' && result.items.length === 1 ? result.items[0] : null
      if (singleItem && singleItem.status !== 'failed') {
        void message.success(tCname('regenerateQueued', { domain: attempt.targets[0]?.domain }))
      } else {
        setBatchResults({ attempt, items: result.items })
      }
      setSelectedKeys([])
      await queryClient.invalidateQueries({ queryKey: ['sites', writeAttempt.owner] })
    },
    onError: (error: unknown, writeAttempt) => {
      const { attempt } = writeAttempt
      if (error === staleSiteAttempt || !currentBatchSessionAccess(attempt.action)) return
      const apiError =
        error instanceof ApiError ? error : new ApiError(t('errors.batchFailed'))
      if (terminalSiteAuthorizationError(apiError)) {
        denyCurrentOwner()
        return
      }
      const uncertain = !batchNotApplied.has(apiError) && writeOutcomeUnknown(error)
      if (uncertain) {
        setBatchRetryLock({
          storageKey: retryStorageKey,
          attempt,
          corrupted: false,
          persistenceFailed: false,
        })
      } else {
        clearPersistedBatchRetry()
      }
      setBatchError(apiError)
      setBatchAttempt(null)
      if (!uncertain && apiError.code === 'version_conflict') {
        void queryClient.invalidateQueries({ queryKey: ['sites', writeAttempt.owner] })
      }
    },
  })

  const writeLocked = retryAttempt !== null || retryCorrupted
  // An unknown batch outcome only holds back new batch writes (one
  // pending record, retried with its own key). Row actions, create, status and
  // lock stay available. A record that no longer parses (older or
  // damaged format) is treated the same way: only batch writes wait, and it can
  // be discarded.
  const managementLocked = batchMutation.isPending || retryStorageChanged
  const batchLocked = managementLocked || writeLocked
  // submitBatchAction stores the retry record before the
  // request goes out (so a reload can recover it), which sets writeLocked.
  // While that fresh submission is still in flight (its confirm dialog is open
  // with loading), the outcome is not unknown yet: show no 结果待确认 notice.
  // A single-row regenerate (submitAttempt without the batch dialog) leaves batchAttempt null;
  // its request is in flight all the same, so the outcome bar waits for the answer.
  const submittingBatch = batchMutation.isPending

  const loadLockDetail = useCallback(
    async (item: SiteListItem, action: LockAction) => {
      const token = currentSessionAccess('sites.manage')
      if (!token) return
      setLockDialog({
        action,
        item,
        detail: null,
        loading: true,
        reason: '',
        error: null,
        attempt: null,
        reloadRequired: false,
        stateMismatch: false,
      })
      setOperationNotice(null)
      try {
        const detail = await sitesApi.detail(token, item.id)
        if (!currentSessionAccess('sites.manage')) return
        if (!detail) throw new ApiError(t('errors.site_not_found'), 404, 'site_not_found')
        cacheSiteDetail(detail, queryOwner)
        setLockDialog((current) => {
          if (!current || current.item.id !== item.id || current.action !== action) return current
          const stateMismatch = !lockActionMatches(action, detail)
          return {
            ...current,
            detail,
            loading: false,
            stateMismatch,
            error: stateMismatch
              ? new ApiError(t('errors.site_lock_state_conflict'), 409, 'site_lock_state_conflict')
              : null,
          }
        })
      } catch (error) {
        if (!currentSessionAccess('sites.manage')) return
        if (terminalSiteAuthorizationError(error)) {
          denyCurrentOwner()
          return
        }
        setLockDialog((current) =>
          current && current.item.id === item.id && current.action === action
            ? {
                ...current,
                loading: false,
                error:
                  error instanceof ApiError
                    ? error
                    : new ApiError(t('errors.stateLoadFailed')),
              }
            : current,
        )
      }
    },
    [cacheSiteDetail, currentSessionAccess, denyCurrentOwner, queryOwner, t],
  )

  const blockAction = useCallback((action: string) => {
    setUnsupportedNotice(t('unsupported.unavailableTitle', { action }))
  }, [t])

  const openCertificateRequest = useCallback(() => {
    if (!canRequestCertificate) return
    // P3：同一用户的网站带 site=，证书页按网站所属用户带入；跨用户时提示按用户分别申请。
    const owners = new Set(selectedItems.map((item) => item.owner?.id ?? ''))
    if (owners.size > 1) {
      setUnsupportedNotice(t('batch.certificateMixedOwners'))
      return
    }
    const domains = selectedItems.map((item) => item.domain.trim()).filter(Boolean)
    const params = new URLSearchParams()
    if (domains.length > 0) params.set('domains', domains.join('\n'))
    if (domains.length > 0 && selectedItems[0]) params.set('site', selectedItems[0].id)
    const query = params.toString()
    navigate(`/site/cert${query ? `?${query}` : ''}`)
  }, [canRequestCertificate, navigate, selectedItems, t])

  const exportSiteDomains = async (targetScopeID?: string) => {
    if (exportPending || !canExportSites) return
    setExportNotice(null)
    if (principal.scope_kind === 'platform' && !targetScopeID) {
      setExportTargetOpen(true)
      return
    }
    const token = currentSessionAccess('sites.export')
    if (!token) return
    const frozenIdentity = exportIdentity
    setExportPending(true)
    try {
      const exportFilters = siteRequestFilters(filters)
      const artifact = await sitesApi.exportDomains(token, targetScopeID ? { ...exportFilters, target_scope_id: targetScopeID } : exportFilters)
      if (
        !currentSessionAccess('sites.export') ||
        activeExportIdentityRef.current !== frozenIdentity
      ) return
      const href = URL.createObjectURL(artifact.blob)
      const link = document.createElement('a')
      link.href = href
      link.download = artifact.filename
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(href)
      setExportNotice({ type: 'success', key: 'success' })
    } catch (error) {
      if (!currentSessionAccess('sites.export') || activeExportIdentityRef.current !== frozenIdentity) return
      setExportNotice({
        type: 'error',
        key: error instanceof ApiError && terminalSiteAuthorizationError(error)
          ? 'errors.forbidden'
          : 'errors.failed',
      })
    } finally {
      if (lineageActiveRef.current) setExportPending(false)
    }
  }

  const reloadLockDetail = async () => {
    if (!lockDialog) return
    const token = currentSessionAccess('sites.manage')
    if (!token) return
    const { action, item } = lockDialog
    setLockDialog((current) =>
      current
        ? {
            ...current,
            loading: true,
            error: null,
            attempt: null,
            reloadRequired: false,
            stateMismatch: false,
          }
        : current,
    )
    try {
      const detail = await sitesApi.detail(token, item.id)
      if (!currentSessionAccess('sites.manage')) return
      if (!detail) throw new ApiError(t('errors.site_not_found'), 404, 'site_not_found')
      cacheSiteDetail(detail, queryOwner)
      setLockDialog((current) => {
        if (!current || current.item.id !== item.id || current.action !== action) return current
        const stateMismatch = !lockActionMatches(action, detail)
        return {
          ...current,
          detail,
          loading: false,
          stateMismatch,
          error: stateMismatch
            ? new ApiError(t('errors.site_lock_state_conflict'), 409, 'site_lock_state_conflict')
            : null,
        }
      })
    } catch (error) {
      if (!currentSessionAccess('sites.manage')) return
      if (terminalSiteAuthorizationError(error)) {
        denyCurrentOwner()
        return
      }
      setLockDialog((current) =>
        current && current.item.id === item.id && current.action === action
          ? {
              ...current,
              loading: false,
              error:
                error instanceof ApiError
                  ? error
                  : new ApiError(t('errors.stateLoadFailed')),
            }
          : current,
      )
    }
  }

  const submitLockAction = () => {
    if (!lockDialog || !lockDialog.detail || lockMutation.isPending ||
      !currentSessionAccess('sites.manage')) return
    if (lockDialog.attempt && lockDialog.error && writeOutcomeUnknown(lockDialog.error)) {
      lockMutation.mutate(lockDialog.attempt)
      return
    }
    if (
      lockDialog.loading ||
      lockDialog.reloadRequired ||
      lockDialog.stateMismatch ||
      !lockActionMatches(lockDialog.action, lockDialog.detail)
    ) {
      return
    }
    const reason = lockDialog.reason.trim()
    if (lockDialog.action === 'lock' && (reason.length === 0 || reason.length > 500)) {
      setLockDialog((current) =>
        current
          ? {
              ...current,
              error: new ApiError(t('errors.validation_error'), 400, 'validation_error'),
            }
          : current,
      )
      return
    }
    const attempt: LockAttempt = {
      action: lockDialog.action,
      id: lockDialog.item.id,
      input:
        lockDialog.action === 'lock'
          ? { expected_version: lockDialog.detail.version, reason }
          : { expected_version: lockDialog.detail.version },
      key: writeKey(lockDialog.action, lockDialog.item.id),
      owner: queryOwner,
      ownerKey,
    }
    setLockDialog((current) => (current ? { ...current, error: null, attempt } : current))
    lockMutation.mutate(attempt)
  }

  const openBatchTargets = useCallback((action: BatchSiteAction, targets: SiteBatchAttempt['targets'], single = false) => {
    if (!canManageSites || batchLocked || targets.length === 0 ||
      !currentBatchSessionAccess(action)) return
    const input: BatchSiteActionRequest = {
      action,
      items: targets.map(({ id, version }) => ({ id, expected_version: version })),
    }
    setBatchError(null)
    setBatchResults(null)
    setBatchAttempt({
      action,
      targets,
      input,
      body: JSON.stringify(input),
      key: writeKey(`batch-${action}`),
      ...(single && targets.length === 1 ? { single: true } : {}),
    })
  }, [batchLocked, canManageSites, currentBatchSessionAccess])

  const openBatchAction = useCallback((action: BatchSiteAction, items = selectedItems) => {
    openBatchTargets(action, items.map(({ id, domain, version }) => ({ id, domain, version })))
  }, [openBatchTargets, selectedItems])

  // A row's 重新生成 is one site's action, worded for that site.
  // 10-27 用户：失败弹窗里点「重新生成」已是确认，直接提交，不再弹确认框和结果框。
  const regenerateSiteNow = useRef<(item: SiteListItem) => void>(() => undefined)
  const openSiteRegenerate = useCallback((item: SiteListItem) => regenerateSiteNow.current(item), [])

  const openStatusDialog = useCallback(() => {
    if (!canManageSites || managementLocked || selectedItems.length === 0 || !currentSessionAccess('sites.manage')) return
    setStatusDialog({
      attempt: {
        status: 'normal',
        targets: selectedItems.map(({ id, domain, version }) => ({ id, domain, version })),
        reason: t('status.lockReason'),
        key: writeKey('status'),
        owner: queryOwner,
        ownerKey,
      },
      error: null,
    })
  }, [canManageSites, currentSessionAccess, managementLocked, ownerKey, queryOwner, selectedItems, t])

  const submitStatus = () => {
    if (!statusDialog || statusMutation.isPending || !currentSessionAccess('sites.manage')) return
    statusMutation.mutate(statusDialog.attempt)
  }

  const submitAttempt = (attempt: SiteBatchAttempt | null) => {
    if (!attempt || batchLocked || !currentBatchSessionAccess(attempt.action)) return
    if (!persistSiteBatchRetry(retryStorageKey, attempt)) {
      setBatchRetryLock({
        storageKey: retryStorageKey,
        attempt: null,
        corrupted: true,
        persistenceFailed: true,
      })
      setBatchError(
        new ApiError(t('errors.retryRecordSaveFailed'), 0, 'retry_lock_corrupted'),
      )
      setBatchAttempt(null)
      return
    }
    setBatchRetryLock({
      storageKey: retryStorageKey,
      attempt,
      corrupted: false,
      persistenceFailed: false,
    })
    batchMutation.mutate({ attempt, owner: queryOwner, ownerKey })
  }
  const submitBatchAction = () => submitAttempt(batchAttempt)
  regenerateSiteNow.current = (item: SiteListItem) => {
    if (!canManageSites || batchLocked || !currentBatchSessionAccess('regenerate_cname')) return
    const input: BatchSiteActionRequest = { action: 'regenerate_cname', items: [{ id: item.id, expected_version: item.version }] }
    setBatchError(null)
    setBatchResults(null)
    submitAttempt({
      action: 'regenerate_cname',
      targets: [{ id: item.id, domain: item.domain, version: item.version }],
      input,
      body: JSON.stringify(input),
      key: writeKey('batch-regenerate_cname'),
      single: true,
    })
  }

  const retryBatchAction = () => {
    if (!retryAttempt || batchMutation.isPending || !currentBatchSessionAccess(retryAttempt.action)) return
    batchMutation.mutate({ attempt: retryAttempt, owner: queryOwner, ownerKey })
  }

  // Drop the unknown-outcome record and reload what the server has.
  const discardBatchRetry = () => {
    if ((!retryAttempt && !retryCorrupted) || batchMutation.isPending) return
    clearPersistedBatchRetry()
    setBatchError(null)
    void queryClient.invalidateQueries({ queryKey: ['sites', queryOwner] })
  }

  const columns = useMemo<TableColumnsType<SiteListItem>>(() => [
      {
        title: t('columns.id'),
        dataIndex: 'display_id',
        // site-parity3a：ID 只放短编号，窄列让域名紧跟。
        // 列宽按实测内容宽度定（单元格左右内边距各 8px），合计见 siteListColumnWidths。
        width: siteListColumnWidths.id,
        render: (_: string, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
      },
      {
        title: t('columns.domain'),
        dataIndex: 'domain',
        width: siteListColumnWidths.domain[role],
        render: (domain: string, item) => (
          <div className="site-domain-cell">
            <Button
              type="link"
              size="small"
              disabled={managementLocked || (role === 'user' && item.lock.locked)}
              title={domain}
              onClick={() => navigate(`/site/${item.id}/edit`)}
            >
              {domain}
            </Button>
            {role === 'admin' ? (
              <span className="site-domain-owner">
                <span className="site-cell-label">{t('columns.owner')}</span>
                {item.owner ? (
                  <Button type="link" size="small" onClick={() => navigate(`/sys/user?display_id=${encodeURIComponent(item.owner!.display_id || '')}`)} disabled={!item.owner.display_id}>
                    {item.owner.display_name} ({item.owner.display_id || item.owner.id})
                  </Button>
                ) : (
                  <span>{t('values.placeholder')}</span>
                )}
              </span>
            ) : null}
          </div>
        ),
      },
      {
        title: t('columns.cname'),
        dataIndex: 'cname',
        width: siteListColumnWidths.cname[role],
        render: (value: string, item) => (
          item.cname_state === 'failed' ? (
            <span className="site-cname-cell site-cname-failed" data-testid="site-cname-failed">
              <CnameFailureActions
                code={item.cname_failure_code}
                reason={cnameFailureText(item.cname_failure_code, item.cname_domain, tCname, i18nInstance.exists, role === 'admin')}
                admin={role === 'admin'}
                siteID={item.id}
                onRegenerate={canRegenerateCname ? () => openSiteRegenerate(item) : undefined}
                regenerateDisabled={batchLocked}
              />
            </span>
          ) : item.cname_state === 'pending' && !value ? (
            <Tag color="processing">{tCname('cell.pending')}</Tag>
          ) : value ? (
            <span className="site-cname-cell">
              <span className="site-cname-value" title={value}>{value}</span>
              <Tooltip title={t('actions.copyCname')}>
                <button
                  type="button"
                  className="site-cname-copy"
                  aria-label={t('actions.copyCname')}
                  onClick={() => { void navigator.clipboard.writeText(value) }}
                >
                  <Copy size={13} aria-hidden="true" />
                </button>
              </Tooltip>
            </span>
          ) : t('values.placeholder')
        ),
      },
      {
        title: t('columns.https'),
        dataIndex: 'https_enabled',
        width: siteListColumnWidths.https,
        // WEB-C01/C05: HTTPS turned on without a bound certificate is not
        // serving yet; it is shown as needing a certificate, not green.
        render: (enabled: boolean, item) => !enabled
          ? canManageSites && !managementLocked && !(role === 'user' && item.lock.locked)
            ? (
              <Tooltip title={tQuick('open')}>
                <button type="button" className="site-https-off-button" aria-label={`${tQuick('open')} ${item.domain}`} onClick={() => setHttpsQuickSite(item)}>
                  <Tag color="default">{t('states.httpsOff')}</Tag>
                </button>
              </Tooltip>
            )
            : <Tag color="default">{t('states.httpsOff')}</Tag>
          : item.https_certificate_bound === false
            ? <Tooltip title={t('states.httpsNoCertificateHint')}><Tag color="warning">{t('states.httpsNoCertificate')}</Tag></Tooltip>
            : <Tag color="success">{t('states.httpsOn')}</Tag>,
      },
      {
        title: t('columns.originListen'),
        key: 'originListen',
        width: siteListColumnWidths.originListen[role],
        // site-parity3a：源站/监听不截断成看不全的半截；放不下时悬浮显示完整列表。
        render: (_, item) => {
          const origins = joinValues(item.origins, language, t('values.placeholder'))
          const ports = item.listen_ports.join(language === 'en-US' ? ', ' : '、')
          return (
            <Tooltip title={<div className="site-origin-tooltip"><div>{t('columns.originLabel')}：{origins}</div><div>{t('columns.listenLabel')}：{ports || t('values.placeholder')}</div></div>}>
              <div className="site-stacked-cell site-origin-listen-cell" tabIndex={0}>
                <span><span className="site-cell-label">{t('columns.originLabel')}</span><span className="site-origin-value">{origins}</span></span>
                <span><span className="site-cell-label">{t('columns.listenLabel')}</span>{item.listen_ports.length > 0 ? item.listen_ports.map((port) => <Tag key={port}>{port}</Tag>) : t('values.placeholder')}</span>
              </div>
            </Tooltip>
          )
        },
      },
      {
        title: t('columns.group'),
        key: 'group',
        width: siteListColumnWidths.group,
        render: (_, item) => (
          <span className="site-ellipsis-value" title={item.group_name || undefined}>{item.group_name || t('values.placeholder')}</span>
        ),
      },
      ...(role === 'admin'
        ? [{
            title: t('columns.regionShort'),
            key: 'region',
            width: siteListColumnWidths.region,
            render: (_: unknown, item: SiteListItem) => {
              if (!item.region) return t('values.placeholder')
              // 区域、线路分两行，窄列也能看全；放不下时悬浮显示全名。
              const text = language === 'en-US'
                ? `${item.region.name} (${item.region.node_group_name})`
                : `${item.region.name}（${item.region.node_group_name}）`
              return (
                <div className="site-stacked-cell" title={text}>
                  <span><span className="site-ellipsis-value">{item.region.name}</span></span>
                  <span className="site-region-line"><span className="site-ellipsis-value">{item.region.node_group_name}</span></span>
                </div>
              )
            },
          }]
        : []),
      {
        title: t('columns.status'),
        key: 'status',
        width: siteListColumnWidths.status,
        render: (_, item) => {
          // L2：停用（enabled=false）的站点运行态投影仍是 normal，这里按停用显示，避免与锁定混淆。
          const operational = operationalSiteStatus(item)
          const value = operational === 'normal' && item.status === 'disabled' ? 'disabled' : operational
          const status = siteStatus[value] ?? { color: 'default' }
          const translationKey = value === 'normal' ? 'active' : value
          return (
            <div className="site-status-cell">
              <Tag color={status.color} icon={value === 'locked' ? <Lock size={12} aria-hidden="true" className="site-status-lock-icon" /> : undefined}>
                {siteStatus[value] ? t(`states.${translationKey}`) : value}
              </Tag>
              {item.traffic_enforcement?.state === 'suspended' && value === 'traffic_exceeded' ? (
                <span className="site-lock-reason">{t('states.trafficSuspended')}</span>
              ) : null}
              {item.traffic_enforcement?.state === 'recovered' && value === 'normal' ? (
                <Tag color="success">{t('states.trafficRecovered')}</Tag>
              ) : null}
              {(() => {
                // 服务端接入状态优先（含节点在线、解析、发布）；CNAME 失败的原因仍在 CNAME 列。
                if (item.access_readiness) {
                  const failing = item.access_readiness.checks.find((check) => !check.ok)
                  if (failing?.code === 'cname_generated' && item.cname_state === 'failed') return null
                  return <SiteAccessStatus readiness={item.access_readiness} />
                }
                const gap = siteAccessGap(item)
                if (gap && item.cname_state !== 'failed') {
                  return <Tooltip title={t(`states.accessGapHint.${gap}`)}><span className="site-lock-reason" data-testid="site-access-gap">{t(`states.accessGap.${gap}`)}</span></Tooltip>
                }
                return null
              })()}
              {item.lock.locked && item.lock.reason ? (
                <Tooltip title={item.lock.reason}>
                  <span className="site-lock-reason">{item.lock.reason}</span>
                </Tooltip>
              ) : null}
            </div>
          )
        },
      },
      {
        title: t('columns.createdAt'),
        dataIndex: 'created_at',
        width: siteListColumnWidths.createdAt,
        // 日期、时间分两行，窄列也能完整显示。
        render: (value: string) => {
          const text = displayDate(value, language, t('values.placeholder'))
          const split = text.indexOf(' ')
          return split > 0
            ? <div className="site-stacked-cell site-created-cell"><span>{text.slice(0, split)}</span><span>{text.slice(split + 1)}</span></div>
            : text
        },
      },
      {
        title: t('columns.actions'),
        key: 'actions',
        width: siteListColumnWidths.actions,
        fixed: 'right',
        render: (_, item) => {
          const tenantLocked = role === 'user' && item.lock.locked
          const menu: MenuProps = {
            items: [
              ...(canReadDNSReconcile ? [{ key: 'dns-reconcile', label: t('actions.dnsReconcile') }] : []),
              ...(canManageLock
                ? [
                    item.lock.locked
                      ? { key: 'unlock', label: t('lock.unlockMenu') }
                      : { key: 'lock', label: t('lock.lockMenu'), danger: true },
                    { type: 'divider' as const },
                  ]
                : []),
              // L2：停用=节点停止服务；锁定=继续服务但禁止用户修改。按当前状态只给一个。
              item.status === 'disabled'
                ? { key: 'enable', label: t('actions.enableSiteMenu'), disabled: tenantLocked || batchLocked }
                : { key: 'disable', label: t('actions.disableSiteMenu'), disabled: tenantLocked || batchLocked },
              { key: 'delete', label: t('actions.delete'), danger: true, disabled: tenantLocked || batchLocked },
              ...(canTransferSite ? [{ key: 'transfer', label: tTransfer('action'), disabled: batchLocked }] : []),
            ],
            onClick: ({ key }) => {
              if (key === 'dns-reconcile') {
                navigate(`/site/${item.id}/dns-reconcile`)
                return
              }
              if (managementLocked) return
              if (key === 'lock' || key === 'unlock') {
                void loadLockDetail(item, key)
                return
              }
              if (key === 'transfer') {
                setTransferSite(item)
                return
              }
              if (tenantLocked) return
              if (key === 'enable' || key === 'disable' || key === 'delete') {
                openBatchAction(key, [item])
              }
            },
          }
          return (
            <div className="site-row-actions">
              <Button
                type="link"
                size="small"
                disabled={managementLocked || tenantLocked}
                onClick={() => navigate(`/site/${item.id}/edit`)}
              >
                {t('actions.manage')}
              </Button>
              <Dropdown menu={menu} trigger={['click']}>
                <Button
                  type="link"
                  size="small"
                  className="site-row-more-button"
                  aria-label={t('actions.more')}
                  title={t('actions.more')}
                  disabled={managementLocked && !canReadDNSReconcile}
                >
                  <Ellipsis size={16} aria-hidden="true" />
                </Button>
              </Dropdown>
            </div>
          )
        },
      },
    ], [batchLocked, canManageLock, canManageSites, canReadDNSReconcile, canRegenerateCname, i18nInstance, language, loadLockDetail, managementLocked, navigate, openBatchAction, openSiteRegenerate, role, t, tCname, tQuick])

  const updateDraft = (key: keyof SiteFilters, value: string) => {
    setAdvancedDraft((current) => ({ ...current, [key]: value }))
  }

  // 查询一次带上行内快速搜索与高级条件；同名字段以行内快速搜索为准。
  const runSearch = (draft: SiteFilters = advancedDraft, quick: string = quickValue) => {
    const cleaned = Object.fromEntries(
      Object.entries(draft).filter(([, value]) => value?.trim()),
    ) as SiteFilters
    const value = quick.trim()
    setAppliedAdvanced(cleaned)
    setAppliedQuickField(value ? quickField : null)
    setFilters(value ? { ...cleaned, [quickField]: value } : cleaned)
    setPage(1)
  }

  // 快速搜索与高级条件边输入边生效（400ms 防抖，下拉选完即查）。
  const draftFilters = (() => {
    const cleaned = Object.fromEntries(Object.entries(advancedDraft).flatMap(([key, value]) => value?.trim() ? [[key, value.trim()]] : [])) as SiteFilters
    return quickValue.trim() ? { ...cleaned, [quickField]: quickValue.trim() } : cleaned
  })()
  useLiveApply(draftFilters, filters, () => runSearch())
  useFilterUrl({ field: appliedQuickField && appliedQuickField !== 'domain' ? appliedQuickField : '', q: appliedQuickField ? filters[appliedQuickField] : '' })
  const idSearchToken = sessionAccessToken ?? ''
  const idSearches = useMemo<Partial<Record<keyof SiteFilters, ReturnType<typeof userSearch>>>>(() => role === 'admin'
    ? { owner: userSearch(idSearchToken), site_ids: siteSearch(idSearchToken, 'id') }
    : { site_ids: siteSearch(idSearchToken, 'id') }, [idSearchToken, role])

  const removeAdvancedFilter = (key: string) => {
    const next = { ...advancedDraft }
    delete next[key as keyof SiteFilters]
    setAdvancedDraft(next)
    runSearch(next)
  }

  const resetSearch = () => {
    setAdvancedDraft({})
    setQuickValue('')
    runSearch({}, '')
  }

  type AdvancedFieldDef = { key: keyof SiteFilters; label: string; placeholder?: string; options?: Array<{ value: string; label: string }> }
  const syncStatusOptions = [
    { value: '', label: t('states.any') },
    { value: 'synced', label: t('states.synced') },
    { value: 'pending', label: t('states.syncing') },
    { value: 'failed', label: t('states.sync_failed') },
  ]
  // 顺序与原高级搜索面板一致（按角色取舍）。
  const advancedFieldDefs: AdvancedFieldDef[] = [
    { key: 'domain', label: t('search.domain'), placeholder: t('search.domainPlaceholder') },
    ...(role === 'user' ? [{ key: 'domains' as const, label: t('search.domains'), placeholder: t('search.domainsPlaceholder') }] : []),
    { key: 'origin_ip', label: t('search.originIp'), placeholder: t('search.originPlaceholder') },
    { key: 'site_ids', label: t('search.siteIds'), placeholder: t('search.siteIdsPlaceholder') },
    ...(role === 'admin' ? [
      { key: 'owner' as const, label: t('search.owner'), placeholder: t('search.ownerPlaceholder') },
      { key: 'domains' as const, label: t('search.domains'), placeholder: t('search.domainsPlaceholder') },
    ] : []),
    ...(role === 'user' ? [{ key: 'group_id' as const, label: t('search.siteGroup'), placeholder: t('search.groupPlaceholder') }] : []),
    ...(role === 'admin' ? [
      { key: 'region_id' as const, label: t('search.region'), placeholder: t('search.regionPlaceholder') },
      { key: 'node_group_id' as const, label: t('search.nodeGroup'), placeholder: t('search.nodeGroupPlaceholder') },
      { key: 'cname_domain' as const, label: t('search.cnameDomain'), placeholder: t('search.cnameDomainPlaceholder') },
      { key: 'cname_hostname' as const, label: t('search.cnameHostname'), placeholder: t('search.cnameHostnamePlaceholder') },
    ] : []),
    { key: 'http_port', label: t('search.httpPort'), placeholder: t('search.portPlaceholder') },
    { key: 'https_port', label: t('search.httpsPort'), placeholder: t('search.portPlaceholder') },
    { key: 'https_enabled', label: t('search.httpsEnabled'), options: triStateOptions },
    { key: 'enabled', label: t('search.siteEnabled'), options: triStateOptions },
    ...(role === 'admin' ? [
      { key: 'is_default' as const, label: t('search.defaultSite'), options: triStateOptions },
      { key: 'sync_status' as const, label: t('search.syncStatus'), options: syncStatusOptions },
    ] : []),
    { key: 'status', label: t('search.siteStatus'), options: statusOptions },
  ]
  const advancedItems: AdvancedFilterItem[] = advancedFieldDefs.map(({ key, label, placeholder, options }) => {
    const value = key === appliedQuickField ? undefined : appliedAdvanced[key]?.trim()
    return {
      key,
      label,
      applied: value ? options?.find((option) => option.value === value)?.label ?? value : undefined,
      field: options
        ? <Select aria-label={label} value={advancedDraft[key] ?? ''} options={options} onChange={(next: string) => updateDraft(key, next)} />
        : idSearches[key]
          ? <IdOrNameInput aria-label={label} value={advancedDraft[key] ?? ''} placeholder={placeholder} freeText search={idSearches[key]} onChange={(next) => updateDraft(key, next)} />
          : <Input aria-label={label} value={advancedDraft[key] ?? ''} placeholder={placeholder} onChange={(event) => updateDraft(key, event.target.value)} />,
    }
  })

  const singleSelected = selectedItems.length === 1 ? selectedItems[0] : null
  const toolbarMenu: MenuProps = {
    items: [
      {
        key: 'batch_modify',
        className: 'site-more-mobile-only',
        label: t('actions.batchModify'),
        disabled: !canManageSites || batchLocked,
      },
      { key: 'enable', label: t('actions.enable'), disabled: !canManageSites || batchLocked || selectedItems.length === 0 },
      { key: 'disable', label: t('actions.disable'), disabled: !canManageSites || batchLocked || selectedItems.length === 0 },
      {
        key: 'delete',
        label: t('actions.delete'),
        danger: true,
        disabled: !canManageSites || batchLocked || selectedItems.length === 0,
      },
      {
        key: 'unlock_blacklist',
        label: t('actions.unlockBlacklist'),
        disabled: !singleSelected,
      },
      // Cache purge lives on the optional cache-control runtime; no entry when it is off.
      ...(!cacheControlOff ? [{
        key: 'clear_cache',
        label: t('actions.clearCache'),
        disabled: !singleSelected,
      }] : []),
      {
        key: 'set_status',
        label: t('actions.setStatus'),
        disabled: !canManageSites || selectedItems.length === 0,
      },
      {
        key: 'cname_domain',
        label: t('search.cnameDomain'),
        disabled: !canManageSites || !singleSelected,
      },
      {
        key: 'cname_mode',
        label: t('actions.cnameMode'),
        disabled: !canManageSites || !singleSelected,
      },
      {
        key: 'node_group',
        label: t('search.nodeGroup'),
        disabled: !canManageSites || !singleSelected,
      },
      // 已验证域名：用户端放到「更多操作」末尾（审计 4.2）。
      ...(role === 'user' ? [{ type: 'divider' as const }, { key: 'verified_domains', label: tDomain('user.title') }] : []),
      ...(canRegenerateCname && selectedItems.length > 0
        ? [{
            key: 'regenerate_cname',
            label: tCname('action'),
            disabled: batchLocked || selectedItems.length === 0,
          }]
        : []),
    ],
    onClick: ({ key }) => {
      if (key === 'batch_modify') {
        setDialog('batch')
        return
      }
      if (key === 'verified_domains') {
        navigate('/account/domains')
        return
      }
      if (key === 'enable' || key === 'disable' || key === 'delete' || key === 'regenerate_cname') {
        openBatchAction(key)
        return
      }
      if (key === 'set_status') {
        openStatusDialog()
        return
      }
      if (!singleSelected) return
      if (key === 'unlock_blacklist') {
        navigate(`/monitor/site/block-log?site_id=${encodeURIComponent(singleSelected.id)}`)
        return
      }
      if (key === 'clear_cache') {
        navigate(`/site/cache-clean?site_id=${encodeURIComponent(singleSelected.id)}`)
        return
      }
      if (key === 'cname_domain' || key === 'cname_mode' || key === 'node_group') {
        navigate(`/site/${singleSelected.id}/edit?tab=basic`)
      }
    },
  }

  const error = query.error instanceof ApiError ? query.error : null
  const forbidden = terminalForbidden || error?.status === 403
  const activeSubnavIndex = { list: 0, groups: 1, defaults: 2, dnsApi: 3, dnsCheck: 4 }[activeSubnav]
  const records = query.data?.items ?? []
  const total = query.data?.total ?? 0
  const batchActionLabel =
    batchAttempt?.action === 'enable'
      ? t('actions.batchEnable')
      : batchAttempt?.action === 'disable'
        ? t('actions.batchDisable')
        : batchAttempt?.action === 'regenerate_cname'
          ? tCname('action')
          : t('actions.batchDelete')
  const retryableBatchItems = batchResults
    ? records.filter((item) =>
        batchResults.items.some((result) => result.id === item.id && result.status === 'failed') &&
        !(role === 'user' && item.lock.locked),
      )
    : []

  const retryFailedBatchItems = () => {
    if (!batchResults || retryableBatchItems.length === 0 || query.isFetching) return
    const action = batchResults.attempt.action
    setBatchResults(null)
    openBatchAction(action, retryableBatchItems)
  }

  return (
    <section className="site-list-page" aria-labelledby="site-list-title">
      <h1 id="site-list-title" className="visually-hidden">
        {t('title')}
      </h1>
      {principal.scope_kind === 'tenant' && sessionAccessToken && sitePrincipalCan(principal, 'sites.read') ? (
        <SiteAutomaticFailureNotice accessToken={sessionAccessToken} ownerKey={ownerKey} enabled={query.isSuccess} />
      ) : null}
      <nav className="site-subnav" aria-label={t('subnav.label')}>
        <button
          className="site-subnav-arrow"
          type="button"
          aria-label={t('subnav.previous')}
          onClick={() => subnavRef.current?.scrollBy({ left: -120, behavior: 'smooth' })}
        >
          <ChevronLeft size={16} aria-hidden="true" />
        </button>
        <div ref={subnavRef} className="site-subnav-scroll">
          {[
            t('subnav.list'),
            t('subnav.groups'),
            t('subnav.defaults'),
            t('subnav.dnsApi'),
            t('subnav.dnsCheck'),
          ].map((item, index) => (index === 2 && !canOpenWebsiteDefaults) || (index === 3 && !canOpenDnsApi) ? null : (
            <button
              className={index === activeSubnavIndex ? 'is-active' : undefined}
              aria-pressed={index < 2 || tenantScope ? index === activeSubnavIndex : undefined}
              type="button"
              key={item}
              onClick={() => {
                if (index < 2) {
                  if (forbidden) return
                  setActiveSubnav(index === 1 ? 'groups' : 'list')
                  return
                }
                if (index === 2) {
                  if (tenantScope) {
                    if (!forbidden) setActiveSubnav('defaults')
                    return
                  }
                  // ui-click F7：平台管理员的网站默认是平台级配置（系统设置 > 网站默认）。
                  navigate('/config/default')
                  return
                }
                if (index === 3) {
                  if (principal.scope_kind === 'tenant') {
                    if (!forbidden) setActiveSubnav('dnsApi')
                    return
                  }
                  navigate('/node/dns')
                  return
                }
                if (index === 4) {
                  if (!canReadDNSReconcile) {
                    blockAction(item)
                    return
                  }
                  // 租户：全站解析检测列表；不再要求先勾选网站。
                  if (!forbidden) setActiveSubnav('dnsCheck')
                }
              }}
            >
              {item}
            </button>
          ))}
        </div>
        <button
          className="site-subnav-arrow"
          type="button"
          aria-label={t('subnav.next')}
          onClick={() => subnavRef.current?.scrollBy({ left: 120, behavior: 'smooth' })}
        >
          <ChevronRight size={16} aria-hidden="true" />
        </button>
      </nav>

      {activeSubnav === 'groups' && !forbidden ? <SiteGroupsPage />
        : activeSubnav === 'dnsApi' && !forbidden && canOpenDnsApi && tenantScope ? <SiteDnsApiPanel />
        : activeSubnav === 'defaults' && !forbidden && canOpenWebsiteDefaults && tenantScope ? <SiteDefaultsPanel />
        : activeSubnav === 'dnsCheck' && !forbidden && canReadDNSReconcile ? <SiteDnsCheckPanel onConfigureDnsApi={() => setActiveSubnav('dnsApi')} restore={routeState?.dnsCheckBack} /> : <>
      <div className="site-toolbar">
        <AdvancedFilters
          className="site-advanced-filters"
          storageKey="site-list"
          columns={4}
          primary={<>
            <Button
              type="primary"
              disabled={managementLocked || !canManageSites}
              onClick={() => setDialog('create')}
            >
              {t('actions.add')}
            </Button>
            <Button
              className="site-batch-button"
              disabled={batchLocked || !canManageSites}
              onClick={() => setDialog('batch')}
            >
              {t('actions.batchModify')}
            </Button>
            <Button disabled={managementLocked || !canRequestCertificate} onClick={openCertificateRequest}>
              {t('actions.requestCertificate')}
            </Button>
            <Dropdown
              menu={toolbarMenu}
              trigger={['click']}
              placement="bottomLeft"
              align={{ offset: [-8, 5] }}
              overlayClassName="site-toolbar-more-popup"
            >
              <Button
                disabled={managementLocked || !canManageSites}
              >
                {t('actions.moreActions')} <ChevronDown size={14} aria-hidden="true" />
              </Button>
            </Dropdown>
            <div className="site-quick-search">
              <Select
                aria-label={t('search.quickFieldLabel')}
                value={quickField}
                onChange={setQuickField}
                options={quickFieldOptions}
                virtual={false}
                listHeight={190}
                classNames={{ popup: { root: 'site-quick-field-popup' } }}
                popupMatchSelectWidth={143}
              />
              {idSearches[quickField]
                ? <IdOrNameInput
                  key={quickField}
                  aria-label={t('search.quickContentLabel')}
                  value={quickValue}
                  placeholder={t('search.quickPlaceholder')}
                  freeText
                  search={idSearches[quickField]}
                  onChange={setQuickValue}
                  onPressEnter={() => runSearch()}
                />
                : <Input
                  aria-label={t('search.quickContentLabel')}
                  value={quickValue}
                  placeholder={quickField === 'domain' ? t('search.domainQuickPlaceholder') : t('search.quickPlaceholder')}
                  onChange={(event) => setQuickValue(event.target.value)}
                  onPressEnter={() => runSearch()}
                />}
            </div>
          </>}
          items={advancedItems}
          onQuery={() => runSearch()}
          onReset={resetSearch}
          onClearAdvanced={() => { setAdvancedDraft({}); runSearch({}) }}
          onRemove={removeAdvancedFilter}
          extra={<>
            <Button
              className="site-export-trigger"
              disabled={!canExportSites}
              icon={<Download size={14} aria-hidden="true" />}
              loading={exportPending}
              onClick={() => void exportSiteDomains()}
            >
              {t('actions.export')}
            </Button>
            {role === 'admin' && (principal.permissions.includes('domains.security.manage') || principal.permissions.includes('platform.admin')) ? (
              <Button className="site-domain-security-trigger" onClick={() => navigate('/site/domain-security')}>
                {tDomain('admin.title')}
              </Button>
            ) : null}
          </>}
        />
      </div>

      {unsupportedNotice ? (
        <Alert
          className="site-operation-notice"
          showIcon
          closable
          type="info"
          message={unsupportedNotice}
          onClose={() => setUnsupportedNotice(null)}
        />
      ) : null}

      <Modal
        open={exportTargetOpen}
        title={tExport('target.title')}
        okText={t('actions.export')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ disabled: !exportTargetScope }}
        onCancel={() => setExportTargetOpen(false)}
        onOk={() => {
          if (!exportTargetScope) return
          setExportTargetOpen(false)
          void exportSiteDomains(exportTargetScope)
        }}
      >
        <TenantScopeSelect
          className="site-export-target"
          accessToken={sessionAccessToken}
          ownerKey={ownerKey}
          canList={principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')}
          queryKeyPrefix="site-export-tenants"
          ariaLabel={tExport('target.label')}
          placeholder={tExport('target.placeholder')}
          emptyText={tExport('target.empty')}
          value={exportTargetScope}
          onChange={setExportTargetScope}
        />
      </Modal>
      {exportNotice ? (
        <Alert
          className="site-operation-notice"
          showIcon
          closable
          type={exportNotice.type}
          message={siteExportNoticeMessage(exportNotice, tExport)}
          onClose={() => setExportNotice(null)}
        />
      ) : null}

      {operationNotice ? (
        <Alert
          className="site-operation-notice"
          showIcon
          closable
          type={operationNotice.type}
          message={siteOperationNoticeMessage(operationNotice, t, tCreate)}
          action={operationNotice.namespace === 'siteCreate' && operationNotice.siteID ? (
            <Button size="small" type="primary" onClick={() => navigate(`/site/${operationNotice.siteID}/edit`)}>
              {tCreate('viewSite')}
            </Button>
          ) : undefined}
          onClose={() => setOperationNotice(null)}
        />
      ) : null}

      {writeLocked && !submittingBatch ? (
        <OutcomeUnknown
          className="site-operation-notice"
          type={retryCorrupted ? 'error' : 'warning'}
          title={retryCorrupted ? t('batch.recoveryFailed')
            : retryAttempt?.single && retryAttempt.action === 'regenerate_cname'
              ? tCname('singleUnknown', { domain: retryAttempt.targets[0]?.domain })
              : t('batch.resultUnknown')}
          detail={retryCorrupted ? t('batch.corruptedDescription') : retryPersistenceFailed ? t('batch.persistenceFailedDescription') : t('batch.retryDescription')}
          action={retryAttempt || retryCorrupted ? (
            <>
              {retryAttempt ? (
                <Button size="small" loading={batchMutation.isPending} onClick={retryBatchAction}>
                  {t('actions.retrySameRequest')}
                </Button>
              ) : null}
              <Popconfirm
                title={t('batch.discardConfirm')}
                okText={t('batch.discard')}
                cancelText={t('actions.cancel')}
                disabled={batchMutation.isPending}
                onConfirm={discardBatchRetry}
              >
                <Button size="small" disabled={batchMutation.isPending}>
                  {t('batch.discard')}
                </Button>
              </Popconfirm>
            </>
          ) : undefined}
        />
      ) : batchError ? (
        <FeedbackWhen title={errorCodeMessage(batchError.code, t)} onClose={() => setBatchError(null)} />
      ) : null}

      {forbidden ? (
        <Result
          className="site-forbidden"
          status="403"
          title={t('errors.forbiddenTitle')}
          subTitle={t('errors.forbiddenDescription')}
        />
      ) : (
        <>
          {query.isError ? (
            <FeedbackWhen title={t('errors.listFailed')} detail={error ? errorCodeMessage(error.code, t) : t('errors.requestFailed')} action={
                <Button
                  size="small"
                  onClick={() => {
                    if (currentSessionAccess('sites.read')) void query.refetch()
                  }}
                >
                  {t('actions.retry')}
                </Button>
              } />
          ) : null}
          {transferSite && currentSessionAccess('sites.manage') ? (
            <SiteTransferModal
              open
              accessToken={currentSessionAccess('sites.manage')!}
              site={{ id: transferSite.id, version: transferSite.version, domain: transferSite.domain, cname: transferSite.cname,
                ownerID: transferSite.owner?.id ?? null, ownerName: transferSite.owner?.display_name ?? '' }}
              canReadUsers={principal.permissions.includes('identity.users.manage') || principal.permissions.includes('platform.admin')}
              onClose={() => setTransferSite(null)}
              onTransferred={() => void queryClient.invalidateQueries({ queryKey: ['sites', queryOwner] })}
            />
          ) : null}
          <SiteHttpsQuickModal
            site={httpsQuickSite}
            accessToken={httpsQuickSite ? currentSessionAccess('sites.manage') : null}
            platform={principal.scope_kind === 'platform'}
            onClose={() => setHttpsQuickSite(null)}
            onSaved={(saved) => {
              cacheSiteDetail(saved, queryOwner)
              void queryClient.invalidateQueries({ queryKey: ['sites', queryOwner] })
              void message.success(tQuick('success'))
            }}
          />
          <div
            className="site-table-scroll site-table-typography"
            data-testid="site-table-scroll"
            aria-busy={query.isPending || query.isFetching}
          >
            <Table<SiteListItem>
              rowKey="id"
              size="small"
              columns={columns}
              dataSource={records}
              loading={query.isPending || query.isFetching}
              pagination={false}
              locale={{ emptyText: query.isPending || query.isError ? ' ' : t('values.empty') }}
              rowSelection={
                canSelectSites
                  ? {
                      columnWidth: siteListColumnWidths.selection,
                      selectedRowKeys: selectedKeys,
                      onChange: setSelectedKeys,
                      getCheckboxProps: (item) => ({
                        disabled: managementLocked || (role === 'user' && item.lock.locked),
                        'aria-label': item.domain,
                      }),
                    }
                  : undefined
              }
              tableLayout="fixed"
              scroll={{ x: siteListTableWidth(role) }}
            />
          </div>
          <Pagination
            className="site-pagination"
            current={page}
            pageSize={limit}
            pageSizeOptions={pageSizes}
            total={total}
            showSizeChanger
            showTotal={(count) => t('values.total', { count })}
            onChange={(nextPage, nextLimit) => {
              setPage(nextLimit === limit ? nextPage : 1)
              setLimit(nextLimit)
            }}
          />
        </>
      )}

      {dialog === 'create' && canManageSites ? (
        <SiteCreateModal
          platform={role === 'admin'}
          owner={queryOwner}
          ownerKey={ownerKey}
          sessionAccess={currentSessionAccess}
          onClose={() => setDialog(null)}
          onCreated={(domain, siteID) => setOperationNotice({
            type: 'success',
            namespace: 'siteCreate',
            key: 'success',
            domain,
            siteID,
          })}
          onForbidden={denyCurrentOwner}
        />
      ) : dialog === 'batch' && canManageSites ? (
        <SiteBatchInputModal
          canRegenerateCname={canRegenerateCname}
          onClose={() => setDialog(null)}
          onPreview={(action, targets) => {
            setDialog(null)
            openBatchTargets(action, targets)
          }}
        />
      ) : null}
      <Modal
        className="site-action-modal"
        title={
          batchResults
            ? batchResults.attempt.single && batchResults.attempt.action === 'regenerate_cname'
              ? tCname('singleResultTitle', { domain: batchResults.attempt.targets[0]?.domain })
              : t('batch.resultsTitle')
            : batchAttempt?.single && batchAttempt.action === 'regenerate_cname'
            ? tCname('singleTitle', { domain: batchAttempt.targets[0]?.domain })
            : batchActionLabel
        }
        open={batchAttempt !== null || batchResults !== null}
        confirmLoading={batchMutation.isPending}
        okText={
          batchAttempt?.action === 'delete'
            ? t('actions.confirmDelete')
            : batchAttempt?.action === 'enable'
              ? t('actions.confirmEnable')
              : batchAttempt?.action === 'regenerate_cname'
                ? tCname('confirm')
                : t('actions.confirmDisable')
        }
        cancelText={t('actions.cancel')}
        okButtonProps={{ danger: batchAttempt?.action === 'delete' }}
        footer={
          batchResults ? (
            <>
              <Button onClick={() => setBatchResults(null)}>
                {t('actions.close')}
              </Button>
              {batchResults.items.some((item) => item.status === 'failed') ? (
                <Button
                  type="primary"
                  disabled={retryableBatchItems.length === 0 || query.isFetching}
                  onClick={retryFailedBatchItems}
                >
                  {tCreate('actions.retryFailed')}
                </Button>
              ) : null}
            </>
          ) : undefined
        }
        onCancel={() => {
          if (batchMutation.isPending) return
          if (batchResults) {
            setBatchResults(null)
            return
          }
          setBatchAttempt(null)
        }}
        onOk={batchResults ? undefined : submitBatchAction}
      >
        {batchResults ? (
          batchResults.items.map((result) => {
            const target = batchResults.attempt.targets.find((item) => item.id === result.id)
            return (
              <p key={result.id}>
                <strong>{target?.domain ?? result.id}</strong>{' '}
                {result.status === 'updated' ? (
                  <Tag color="success">
                    {batchResults.attempt.action === 'enable' ? t('states.enabled') : t('states.disabled')}
                  </Tag>
                ) : result.status === 'deleted' ? (
                  <Tag color="success">{t('states.deleted')}</Tag>
                ) : result.status === 'queued' ? (
                  <>
                    <Tag color="processing">{tCname('queued')}</Tag>
                    <span>{tCname('taskID', { id: result.site.basic.cname_task_id })}</span>
                  </>
                ) : (
                  <Tag color="error">
                    {batchResults.attempt.action === 'regenerate_cname'
                      ? cnameErrorCodeMessage(result.error.code, tCname)
                      : errorCodeMessage(result.error.code, t)}
                  </Tag>
                )}
              </p>
            )
          })
        ) : batchAttempt ? (
          batchAttempt.action === 'delete' ? (
            // 删除只确认一次：写清删哪些站点、不可恢复、会撤下 CNAME 解析与节点配置。
            <Alert
              showIcon
              type="warning"
              message={batchAttempt.targets.length === 1
                ? t('batch.deleteSingle', { domain: batchAttempt.targets[0]!.domain })
                : t('batch.deleteMany', {
                  count: batchAttempt.targets.length,
                  domains: batchAttempt.targets.slice(0, 5).map((target) => target.domain).join(language === 'en-US' ? ', ' : '、') +
                    (batchAttempt.targets.length > 5 ? t('batch.deleteMore', { count: batchAttempt.targets.length - 5 }) : ''),
                })}
              description={t('batch.deleteConsequence')}
            />
          ) : (
            <Alert
              showIcon
              type="info"
              message={batchAttempt.single && batchAttempt.action === 'regenerate_cname'
                ? tCname('singleSummary', { domain: batchAttempt.targets[0]?.domain })
                : t('batch.actionSummary', { count: batchAttempt.targets.length, action: batchActionLabel })}
              description={<>
                {batchAttempt.action === 'disable' || batchAttempt.action === 'enable'
                  ? <p className="site-batch-impact">{t(batchAttempt.action === 'disable' ? 'batch.disableImpact' : 'batch.enableImpact')}</p>
                  : null}
                {batchAttempt.single ? null : batchAttempt.targets.map((target) => target.domain).join(language === 'en-US' ? ', ' : '、')}
              </>}
            />
          )
        ) : null}
      </Modal>
      <SiteLockModal
        state={lockDialog}
        pending={lockMutation.isPending}
        onCancel={() => setLockDialog(null)}
        onReasonChange={(reason) =>
          setLockDialog((current) =>
            current
              ? {
                  ...current,
                  reason,
                  error: current.error?.code === 'validation_error' ? null : current.error,
                }
              : current,
          )
        }
        onReload={() => void reloadLockDetail()}
        onSubmit={submitLockAction}
      />
      <SiteStatusModal
        state={statusDialog}
        pending={statusMutation.isPending}
        canLock={canManageLock && principal.scope_kind === 'platform'}
        onCancel={() => {
          if (!statusMutation.isPending) setStatusDialog(null)
        }}
        onStatusChange={(status) =>
          setStatusDialog((current) => current ? {
            ...current,
            error: null,
            attempt: { ...current.attempt, status },
          } : current)
        }
        onSubmit={submitStatus}
      />
      </>}
    </section>
  )
}

const cnamePendingPollIntervalMs = 2000
const cnamePendingPollWindowMs = 60_000

export default function SiteListPage() {
  const { t } = useTranslation('sites')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!principal || !accessToken || !sessionEpoch) return null

  const owner = siteSessionOwner(principal, sessionEpoch)
  if (!owner || !sitePrincipalCan(principal, 'sites.read')) {
    return (
      <Result
        className="site-forbidden"
        status="403"
        title={t('errors.forbiddenTitle')}
        subTitle={t('errors.forbiddenDescription')}
      />
    )
  }
  const ownerKey = JSON.stringify(owner)
  return (
    <SiteListPageSession
      key={ownerKey}
      principal={principal}
      owner={owner}
      ownerKey={ownerKey}
      role={roleForPrincipal(principal)}
    />
  )
}
