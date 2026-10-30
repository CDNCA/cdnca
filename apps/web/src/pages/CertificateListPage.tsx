import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App,
  Button,
  Dropdown,
  Form,
  Input,
  Modal,
  Pagination,
  Popconfirm,
  Result,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  type TableColumnsType,
} from 'antd'
import { ArrowLeft, ChevronDown, CircleCheck, Download, MoreHorizontal, Pencil, Plus, RefreshCw, Trash2, Upload } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import AcmeCACredentialsCard from './system-settings/AcmeCACredentialsCard'
import '../i18n/systemSettings'

import { ApiError, type Principal } from '../api/auth'
import { samePEMCertificateChain } from './certificatePEM'
import {
  certificatesApi,
  type CertificateAsset,
	  type CertificateAssetSource,
	  type CertificateAssetBinding,
	  type CertificateAssetDetail,
  type CertificateAssetVersion,
  type CertificateChallengeType,
  type CertificateOrder,
	  type CertificateOrderStatus,
	  type BindCertificateAssetInput,
	  type CertificateDefaultType,
	  type UpdateCertificateDefaultsInput,
  type CreateCertificateOrderInput,
  type ImportCertificateAssetInput,
  type CertificateAssetStatusFilter,
  type CertificateAssetListFilters,
  type CertificateIssuer,
} from '../api/certificates'
import { dnsApi, type DNSProvider } from '../api/dns'
import { usersApi, type ManagedUser } from '../api/users'
import { sitesApi } from '../api/sites'
import { pemFileAccept, readPEMFile, type PEMFileError, type PEMFileKind } from './certificateFiles'
import { useSessionStore } from '../auth/session'
import { localizedUnknownApiError } from '../i18n/apiError'
import '../i18n/certificateAssets'
import '../i18n/dnsProviders'
import { CertificateFailureReason } from '../components/CertificateFailureReason'
import { formatDateTime } from '../i18n/formatters'
import {
  credentialFields,
  isCreatableProviderType,
  ProviderEditor,
  type DNSProviderEditorState,
  type ProviderForm,
} from './NodeDnsPage'
import './CertificateListPage.css'
import { AdvancedFilters, FeedbackWhen, OutcomeUnknown, fieldReasonText, submitErrorFields, useFormSubmitError, IdOrNameInput, useLiveApply, type AdvancedFilterItem, type FormErrorMap } from '@cdnca/ui'
import { certificateSearch, userSearch } from './idNameSources'

// Order fields named differently on the form: the domains
// are one textarea, so domains / domains[n] mark it.
// PATCH /v1/certificate-defaults fields the 默认设置 selects show refusals for.
const defaultFieldNames = new Set(['certificate_type', 'issuer', 'dns_provider_id'])

const orderErrorMap: FormErrorMap = Object.fromEntries([
  ['domains', 'domains_text'],
  ...Array.from({ length: 100 }, (_, index) => [`domains[${index}]`, 'domains_text']),
])

interface CertificateForm {
  target_scope_id?: string
  name?: string
  remark?: string
  domains_text: string
  challenge_type: CertificateChallengeType
  dns_provider_id?: string
  auto_renew: boolean
}

interface WriteAttempt {
  input: CreateCertificateOrderInput
  key: string
}

// 批量申请：每行一张证书、一个独立订单（独立幂等键）。结果未知的行只能用原键重试。
type BatchRowStatus = 'pending' | 'running' | 'accepted' | 'failed' | 'unknown'
interface BatchRow {
  line: number
  domains: string[]
  input: CreateCertificateOrderInput
  key: string
  status: BatchRowStatus
  error?: ApiError
}

interface CertificateDefaultsAttempt {
  input: UpdateCertificateDefaultsInput
  key: string
}

type ProviderWriteIntent =
  | { kind: 'create'; input: import('../api/dns').CreateDNSProviderInput }
  | { kind: 'update'; id: string; providerType: string; input: import('../api/dns').UpdateDNSProviderInput }
  | { kind: 'verify'; id: string; providerType: string; version: number }
  | { kind: 'delete'; id: string; version: number }
type ProviderWriteAttempt = ProviderWriteIntent & { key: string }

interface AssetUploadForm {
  name: string
  remark?: string
  certificate_pem: string
  private_key_pem: string
}

interface AssetBindForm {
	site_id: string
	version_id: string
	default: boolean
}

interface AssetTarget {
  asset: CertificateAsset
  version?: CertificateAssetVersion
}

interface AssetWriteAttempt {
  input: ImportCertificateAssetInput
  targetScopeID?: string
  targetTenantID?: string
  key: string
  requestID: string
}

type AssetCommandAttempt =
	| { kind: 'activate'; target: Required<AssetTarget>; key: string; requestID: string }
	| { kind: 'delete'; asset: CertificateAsset; key: string; requestID: string }
	| { kind: 'bind'; target: Required<AssetTarget>; input: BindCertificateAssetInput; key: string; requestID: string }
	| { kind: 'unbind'; asset: CertificateAsset; binding: CertificateAssetBinding; key: string; requestID: string }

type CertificatePermission = 'certificates.read' | 'certificates.manage' | 'dns.read' | 'dns.manage' | 'sites.read' | 'edge_publications.read'
type CertificateOwner =
  | readonly ['tenant', string, string, string, number]
  | readonly ['platform', string | null, string | null, string, number, string, string | null]

interface CertificateTargetUser {
  id: string
  username: string
  displayID?: string
}

type BulkAction = 'enable' | 'disable' | 'enableAutoRenew' | 'disableAutoRenew' | 'download' | 'delete'

interface CertificateAssetRow {
  asset: CertificateAsset
  detail?: CertificateAssetDetail
  version?: CertificateAssetVersion
  order?: CertificateOrder
  /** 同域名有尚未出结果的申请（重新申请/续签进行中） */
  inFlight: boolean
  filter: ReturnType<typeof assetStatusFilter>
}

interface CertificateFilterDraft {
  domain: string
  multiDomain: string
  user: string
  certificateID: string
  name: string
  remark: string
  type?: CertificateAssetSource
  dnsApi?: string
  expiresAt?: '30' | '90' | 'expired'
  enabled?: 'on' | 'off'
  issueStatus?: 'issued' | 'failed'
  syncStatus?: 'complete' | 'pending' | 'failed'
}

const emptyFilterDraft: CertificateFilterDraft = { domain: '', multiDomain: '', user: '', certificateID: '', name: '', remark: '' }

// CERT-05：高级筛选整体交给服务端（列表、总数、状态计数同一条件），不再只筛当前页。
function serverAssetFilters(draft: CertificateFilterDraft): CertificateAssetListFilters {
  const text = (value: string) => value.trim() || undefined
  const domains = draft.multiDomain.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean)
  return {
    domain: text(draft.domain),
    domains: domains.length > 0 ? domains : undefined,
    user: text(draft.user),
    certificate_id: text(draft.certificateID),
    name: text(draft.name),
    remark: text(draft.remark),
    source: draft.type,
    dns_provider_id: draft.dnsApi,
    expiry: draft.expiresAt === '30' ? 'within30' : draft.expiresAt === '90' ? 'within90' : draft.expiresAt,
    auto_renew: draft.enabled ? draft.enabled === 'on' : undefined,
    issue: draft.issueStatus,
    sync: draft.syncStatus,
  }
}

function certificateOwner(principal: Principal, sessionEpoch: number, target?: ManagedUser): CertificateOwner | null {
  if (!principal.scope_id || !principal.user_id || !sessionEpoch) return null
  if (principal.scope_kind === 'tenant') {
    if (!principal.tenant_id) return null
    return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
  }
  if (principal.tenant_id !== null || (target && (!target.scope_id || !target.tenant_id || !target.id))) return null
  return ['platform', target?.scope_id ?? null, target?.tenant_id ?? null, principal.user_id, sessionEpoch, principal.scope_id, target?.id ?? null]
}

function currentCertificateSessionMatches(owner: CertificateOwner): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return false
  if (owner[0] === 'tenant') {
    const currentOwner = certificateOwner(principal, sessionEpoch)
    return Boolean(currentOwner && JSON.stringify(currentOwner) === JSON.stringify(owner))
  }
  return principal.scope_kind === 'platform' && principal.tenant_id === null &&
    principal.scope_id === owner[5] && principal.user_id === owner[3] && sessionEpoch === owner[4]
}

function currentCertificateSessionAccess(owner: CertificateOwner, permission: CertificatePermission): string | null {
  const { accessToken, principal } = useSessionStore.getState()
  if (!accessToken || !principal ||
    (!principal.permissions.includes(permission) && !principal.permissions.includes('platform.admin'))) return null
  return currentCertificateSessionMatches(owner) ? accessToken : null
}

function canManageCertificatePermission(principal: Principal, permission: CertificatePermission): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

// 按实测内容宽度（14px 字号，单元格左右内边距各 10px）规划的列宽，固定表格布局。
// 1440 下表格可用约 1098，两张表合计都按约 1080 排，1440 起不出横向滚动，更宽时各列按比例放宽；
// 1280 下可用约 940，保留横向滚动（证书列表操作列固定在右侧）。
// 证书列表：日期、时间分两行；操作按钮两行排开。申请记录：失败原因占剩余宽度，最多两行，超出悬浮看全文。
const certificateColumnWidths = {
  assets: {
    selection: 60, id: 52, user: 144, certificate: 192, type: 76, createdAt: 100, expiresAt: 100,
    autoRenew: 80, status: 76, actions: 200,
  },
  orders: { domains: 200, challenge: 96, status: 76, autoRenew: 80, notAfter: 100, failure: 428, createdAt: 100 },
} as const

function certificateTableWidth(widths: Readonly<Record<string, number>>, omit: readonly string[] = []): number {
  return Object.entries(widths).reduce((sum, [key, width]) => omit.includes(key) ? sum : sum + width, 0)
}

// 日期与时间分两行，窄列也能完整显示。
function stackedDateTime(text: string) {
  const split = text.indexOf(' ')
  return split > 0
    ? <span className="certificate-stacked-cell"><span>{text.slice(0, split)}</span><span>{text.slice(split + 1)}</span></span>
    : text
}

function invalidCertificateResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function certificatePermissionDenied(): ApiError {
  return new ApiError('Certificate permission denied', 403, 'permission_denied')
}

function assertAssetOwner(owner: CertificateOwner, value: CertificateAsset, expectedID?: string, expectedScope?: string): void {
  if ((owner[0] === 'tenant' && value.tenant_scope_id !== owner[1]) ||
    (expectedScope && value.tenant_scope_id !== expectedScope) || (expectedID && value.id !== expectedID)) {
    throw invalidCertificateResponse()
  }
}

function assertOrderOwner(owner: CertificateOwner, value: CertificateOrder, expectedScope?: string): void {
  if ((owner[0] === 'tenant' && value.scope_id !== owner[1]) || (expectedScope && value.scope_id !== expectedScope)) throw invalidCertificateResponse()
}

function orderReceiptMatches(value: CertificateOrder, input: CreateCertificateOrderInput): boolean {
  return JSON.stringify(value.domains) === JSON.stringify(input.domains) &&
    value.challenge_type === input.challenge_type &&
    value.dns_provider_id === input.dns_provider_id &&
    value.auto_renew === input.auto_renew &&
    (input.issuer === undefined || value.issuer === input.issuer)
}

// 卡片顺序：ZeroSSL 在前；只列平台已配置的 CA（Let's Encrypt 无需配置）。
const issuerCardOrder: CertificateIssuer[] = ['zerossl', 'lets_encrypt', 'google_trust']
const batchLineLimit = 50

interface BatchForm {
  lines: string
  dns_provider_id?: string
}

function assertProviderOwner(owner: CertificateOwner, value: DNSProvider, expectedScope = owner[1]): void {
  if (!expectedScope || value.scope_id !== expectedScope) throw invalidCertificateResponse()
}

function assertAssetDetail(owner: CertificateOwner, value: CertificateAssetDetail, expectedID?: string, expectedScope?: string): void {
  assertAssetOwner(owner, value.asset, expectedID, expectedScope)
  for (const version of value.versions) {
    if (version.tenant_scope_id !== value.asset.tenant_scope_id || version.asset_id !== value.asset.id) {
      throw invalidCertificateResponse()
    }
  }
}

function assertBinding(
  owner: CertificateOwner,
  value: CertificateAssetBinding,
  assetID: string,
  versionIDs: ReadonlySet<string>,
  expectedSiteID?: string,
  expectedScope = owner[1],
): void {
  if (
    !expectedScope || value.tenant_scope_id !== expectedScope || value.asset_id !== assetID ||
    !versionIDs.has(value.version_id) || (expectedSiteID && value.site_id !== expectedSiteID)
  ) throw invalidCertificateResponse()
}

const hostLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

function normalizeDomain(raw: string): string | null {
  let value = raw.trim().toLowerCase().replace(/\.$/, '')
  const wildcard = value.startsWith('*.')
  if (wildcard) value = value.slice(2)
  if (!value || value.length > 253 || [...value].some((character) => character.codePointAt(0)! > 127)) return null
  if (value.split('.').some((label) => !hostLabelPattern.test(label))) return null
  return wildcard ? `*.${value}` : value
}

function normalizedDomains(raw: string): string[] | null {
  // “多个域名用空格分隔”：换行、逗号、空白都作分隔
  const source = raw.split(/[\s,]+/).filter(Boolean)
  if (source.length < 1 || source.length > 100) return null
  const domains = source.map(normalizeDomain)
  if (domains.some((value) => value === null)) return null
  const result = domains as string[]
  if (new Set(result).size !== result.length) return null
  return result.sort()
}

function writeKey(): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `certificate-order-create-${suffix}`
}

function providerWriteKey(kind: ProviderWriteIntent['kind']): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `certificate-dns-provider-${kind}-${suffix}`
}

function clearProviderWriteCredentials(attempt: ProviderWriteAttempt | null): void {
  const credentials = attempt?.kind === 'create' || attempt?.kind === 'update' ? attempt.input.credentials : undefined
  if (!credentials) return
  for (const key of Object.keys(credentials)) credentials[key] = ''
}

function requestID(): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `certificate-asset-${suffix}`
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

// The server answered a certificate order with 5xx: the order may have been
// committed, and replaying the same body and Idempotency-Key returns its
// stored result (or places it once). A network failure (status 0, 408) or a
// receipt that failed our own integrity check (invalid_response) stays
// "outcome unknown".
function orderServerFailure(error: unknown): boolean {
  return error instanceof ApiError && error.status >= 500 && error.code !== 'invalid_response'
}

function orderOutcomeUnknown(error: unknown): boolean {
  return outcomeUnknown(error) && !orderServerFailure(error)
}

// 重新申请沿用原订单的域名、验证方式、DNS 服务商、自动续期与签发机构（10-26 用户实机）。
function reapplyOrderInput(order: CertificateOrder, targetScopeID?: string): CreateCertificateOrderInput {
  return {
    domains: [...order.domains],
    challenge_type: order.challenge_type,
    auto_renew: order.auto_renew,
    ...(order.name ? { name: order.name } : {}),
    ...(order.remark ? { remark: order.remark } : {}),
    ...(order.issuer ? { issuer: order.issuer } : {}),
    ...(targetScopeID ? { target_scope_id: targetScopeID } : {}),
    ...(order.challenge_type === 'dns-01' && order.dns_provider_id ? { dns_provider_id: order.dns_provider_id } : {}),
  }
}

// 申请记录与“申请中”共用：同一组域名（不区分大小写、不计顺序）。
function sameDomainSet(domains: string[], sans: string[]): boolean {
  const set = new Set(sans.map((domain) => domain.toLowerCase()))
  return set.size > 0 && domains.length === set.size && domains.every((domain) => set.has(domain.toLowerCase()))
}

// 尚未出结果的申请（签发后会生成新证书，不再算这一行“申请中”）。
const inFlightOrderStatuses = new Set<CertificateOrderStatus>(['pending', 'validating', 'issuing'])

// 只有 ACME 证书、且申请晚于当前版本导入时间、尚未产出证书，才算这一行“申请中”。
// 早于当前版本的未结订单（如被 CA 复用 order 后卡住的旧申请）不再让新签发的证书一直标“申请中”。
function orderInFlightFor(order: CertificateOrder, asset: CertificateAsset, version: CertificateAssetVersion): boolean {
  return asset.source === 'acme' && order.scope_id === asset.tenant_scope_id &&
    inFlightOrderStatuses.has(order.status) && !order.issued_asset_id &&
    Date.parse(order.created_at) >= Date.parse(version.imported_at) && sameDomainSet(order.domains, version.sans)
}

// 验证/签发正常几分钟完成；超过 1 小时仍未结束的申请在申请记录里提示卡住。
const stuckOrderAfterMs = 60 * 60 * 1000
function orderStuck(order: CertificateOrder, now: number): boolean {
  return inFlightOrderStatuses.has(order.status) && now - Date.parse(order.created_at) > stuckOrderAfterMs
}

function errorMessage(error: ApiError, t: TFunction): string {
  const knownCodes = new Set([
    'validation_error', 'permission_denied', 'dns_resource_not_found', 'dns_resource_conflict',
    'idempotency_conflict', 'credential_encryption_unavailable', 'certificate_defaults_not_found',
    'version_conflict',
    'certificate_asset_invalid_request', 'certificate_asset_invalid_certificate_pem',
    'certificate_asset_owner_required',
    'certificate_asset_invalid_private_key_pem', 'certificate_asset_key_mismatch',
    'certificate_asset_permission_denied', 'certificate_asset_not_found',
    'certificate_asset_revision_conflict', 'certificate_asset_idempotency_conflict',
		'certificate_asset_referenced', 'certificate_asset_invalid_transition',
		'certificate_asset_domain_not_covered', 'certificate_asset_auto_renew_unsupported',
    'domain_blocked', 'certificate_issuer_unavailable', 'certificate_order_in_flight', 'certificate_target_required',
    'certificate_asset_envelope_unavailable', 'certificate_asset_internal_error',
  ])
  return knownCodes.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.request_failed'))
}

function statusColor(status: CertificateOrderStatus): string {
  if (status === 'active' || status === 'issued') return 'success'
  if (status === 'failed' || status === 'revoked') return 'error'
  if (status === 'renewal_due') return 'warning'
  return 'processing'
}

type AssetStatusFilter = 'all' | 'normal' | 'expiring' | 'expired' | 'autoRenew' | 'manualRenew'
const assetStatusQuery: Record<Exclude<AssetStatusFilter, 'all'>, CertificateAssetStatusFilter> = {
  normal: 'normal', expiring: 'expiring', expired: 'expired', autoRenew: 'auto_renew', manualRenew: 'manual_renew',
}

function latestAssetVersion(detail: CertificateAssetDetail | undefined): CertificateAssetVersion | undefined {
  return detail?.versions.reduce<CertificateAssetVersion | undefined>(
    (latest, version) => !latest || version.version > latest.version ? version : latest,
    undefined,
  )
}

function assetStatusFilter(version: CertificateAssetVersion | undefined, now = Date.now()): 'normal' | 'expiring' | 'expired' | 'other' {
  if (!version) return 'other'
  const expiresAt = Date.parse(version.not_after)
  if (version.status === 'expired' || Number.isFinite(expiresAt) && expiresAt <= now) return 'expired'
  if ((version.status === 'active' || version.status === 'default') && expiresAt - now <= 30 * 24 * 60 * 60 * 1000) return 'expiring'
  if (version.status === 'active' || version.status === 'default') return 'normal'
  return 'other'
}

function csvValue(value: string): string {
  return `"${value.replaceAll('"', '""')}"`
}

export default function CertificateListPage() {
  const { t } = useTranslation('certificates')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null
  if (!canManageCertificatePermission(principal, 'certificates.read')) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }
  if (principal.scope_kind === 'platform') {
    if (principal.tenant_id !== null || !principal.scope_id || !principal.user_id || !sessionEpoch) {
      return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
    }
    const actorKey = JSON.stringify([principal.scope_kind, principal.scope_id, principal.user_id, sessionEpoch])
    return <PlatformCertificateListPage key={actorKey} principal={principal} sessionEpoch={sessionEpoch} />
  }

  const owner = certificateOwner(principal, sessionEpoch)
  if (!owner) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }

  const ownerKey = JSON.stringify(owner)
  return (
    <section className="identity-page certificate-page" aria-labelledby="certificate-list-title">
      <CertificateListPageContent
        key={ownerKey}
        owner={owner}
        targetUser={{ id: principal.user_id, username: principal.username }}
        canManage={canManageCertificatePermission(principal, 'certificates.manage')}
        canReadDNS={canManageCertificatePermission(principal, 'dns.read')}
        canManageDNS={canManageCertificatePermission(principal, 'dns.manage')}
      />
    </section>
  )
}

function CertificateOwnerPicker({ owner, value, onChange, disabled, label }: {
  owner: CertificateOwner
  value: ManagedUser | null
  onChange: (value: ManagedUser | null) => void
  disabled?: boolean
  label?: string
}) {
  const { t } = useTranslation('certificateAssets')
  const [search, setSearch] = useState('')
  const term = useDeferredValue(search.trim())
  // GET /v1/admin/users needs identity.users.manage, which certificates.read does not imply.
  const canListUsers = useSessionStore((state) => state.principal?.permissions.some((code) => code === 'identity.users.manage' || code === 'platform.admin') ?? false)
  const usersQuery = useQuery({
    queryKey: ['certificate-target-users', ...owner, term],
    enabled: canListUsers,
    retry: false,
    queryFn: async () => {
      const token = currentCertificateSessionAccess(owner, 'certificates.read')
      if (!token) throw certificatePermissionDenied()
      const result = await usersApi.list(token, {
        page: 1, limit: 100,
        ...(term ? (/^[1-9]\d*$/.test(term) ? { display_id: term } : { search: term }) : {}),
      })
      if (!currentCertificateSessionAccess(owner, 'certificates.read')) throw invalidCertificateResponse()
      return result
    },
  })
  const users = (usersQuery.data?.items ?? []).filter((item) => item.status === 'active')
  const selected = value && value.status === 'active' && !users.some((item) => item.id === value.id) ? [value] : []
  return (
    <div style={{ minWidth: 0 }}>
      <Select
        showSearch allowClear filterOption={false}
        style={{ width: '100%' }}
        aria-label={label ?? t('target.label')}
        value={value?.id} disabled={disabled}
        options={[...selected, ...users].map((item) => ({
          value: item.id, label: t('target.option', { username: item.username, displayID: item.display_id }),
        }))}
        loading={usersQuery.isPending || usersQuery.isFetching}
        placeholder={t('target.placeholder')}
        onSearch={setSearch}
        onChange={(id: string | undefined) => onChange(id ? users.find((item) => item.id === id) ?? selected.find((item) => item.id === id) ?? null : null)}
        notFoundContent={t(canListUsers && usersQuery.isPending ? 'target.loading' : 'target.empty')}
      />
      {!canListUsers ? <Alert type="warning" showIcon message={t('target.noUserPermission')} /> : null}
      {usersQuery.error ? <FeedbackWhen title={t(usersQuery.error instanceof ApiError && usersQuery.error.status === 403 ? 'target.forbidden' : 'target.loadFailed')} action={<Button size="small" disabled={disabled} onClick={() => {
          if (currentCertificateSessionAccess(owner, 'certificates.read')) void usersQuery.refetch()
        }}>{t('actions.retry')}</Button>} /> : null}
    </div>
  )
}

// CERT-02：本地读取证书/私钥文件，填入下方文本框（保留粘贴）。
// 读取结果只落到发起它的那份草稿：弹窗已关闭/重开（本组件已卸载）、又选了新文件、
// 或读取期间字段被手改（current() 与开始时不同）时丢弃，不覆盖新内容。
function PEMFileButton({ kind, disabled, current, onRead, onError }: {
  kind: PEMFileKind
  disabled?: boolean
  current: () => unknown
  onRead: (text: string) => void
  onError: (error: PEMFileError) => void
}) {
  const { t } = useTranslation('certificateAssets')
  const inputRef = useRef<HTMLInputElement>(null)
  const readRef = useRef(0)
  useEffect(() => () => { readRef.current = -1 }, [])
  const label = t(kind === 'certificate' ? 'upload.certificateFile' : 'upload.privateKeyFile')
  return (
    <div className="certificate-pem-file">
      <input
        ref={inputRef} type="file" hidden disabled={disabled} accept={pemFileAccept[kind]} aria-label={label}
        onChange={(event) => {
          const file = event.target.files?.[0]
          event.target.value = ''
          if (!file || readRef.current < 0) return
          const read = ++readRef.current
          const before = current()
          void readPEMFile(file, kind).then((result) => {
            if (readRef.current !== read || current() !== before) return
            if ('text' in result) onRead(result.text)
            else onError(result.error)
          })
        }}
      />
      <Button size="small" icon={<Upload size={13} />} disabled={disabled} onClick={() => inputRef.current?.click()}>{label}</Button>
    </div>
  )
}

// CERT-02：绑定网站选本人网站（按域名搜索），列出证书是否覆盖该网站主域名；
// 平台管理员只列证书归属用户的网站。无 sites.read 时回退为手填网站 ID。
function CertificateSiteSelect({ ownerID, sans, id, value, onChange }: {
  ownerID?: string
  sans: string[]
  id?: string
  value?: string
  onChange?: (value: string) => void
}) {
  const { t } = useTranslation('certificateAssets')
  const [search, setSearch] = useState('')
  const term = useDeferredValue(search.trim())
  const canRead = useSessionStore((state) => Boolean(state.principal?.permissions.some((code) => code === 'sites.read' || code === 'platform.admin')))
  const platform = useSessionStore((state) => state.principal?.scope_kind === 'platform')
  const ready = !platform || Boolean(ownerID)
  const query = useQuery({
    queryKey: ['certificate-bind-sites', ownerID ?? '', term],
    enabled: canRead && ready,
    retry: false,
    queryFn: async () => (await sitesApi.list(useSessionStore.getState().accessToken ?? '', {
      page: 1, limit: 50, ...(ownerID ? { owner: ownerID } : {}), ...(term ? { domain: term } : {}),
    })).items,
  })
  if (!canRead || !ready) {
    return <Input id={id} autoComplete="off" value={value} placeholder={t('bind.siteIDPlaceholder')} onChange={(event) => onChange?.(event.target.value.trim())} />
  }
  return (
    <Select
      id={id} showSearch allowClear filterOption={false} value={value || undefined}
      aria-label={t('bind.site')} placeholder={t('bind.sitePlaceholder')}
      loading={query.isFetching} onSearch={setSearch}
      onChange={(next: string | undefined) => onChange?.(next ?? '')}
      notFoundContent={query.isFetching ? null : t(query.isError ? 'bind.sitesFailed' : 'bind.sitesEmpty')}
      options={(query.data ?? []).map((site) => {
        const covered = certificateCoversDomain(sans, site.domain)
        return { value: site.id, label: t(covered ? 'bind.siteOption' : 'bind.siteOptionUncovered', { domain: site.domain, id: site.display_id }) }
      })}
    />
  )
}

// Mirrors certificateasset.CoversDomain: exact SAN, or a wildcard covering one label.
function certificateCoversDomain(sans: string[], domain: string): boolean {
  const target = domain.trim().toLowerCase().replace(/\.$/, '')
  return sans.some((raw) => {
    const san = raw.trim().toLowerCase().replace(/\.$/, '')
    if (san === target) return true
    if (!san.startsWith('*.')) return false
    const suffix = san.slice(1)
    return target.endsWith(suffix) && !target.slice(0, -suffix.length).includes('.') && target.length > suffix.length
  })
}

function PlatformCertificateListPage({ principal, sessionEpoch }: { principal: Principal; sessionEpoch: number }) {
  const [targetUser, setTargetUser] = useState<ManagedUser | null>(null)
  const [section, setSection] = useState<'list' | 'default' | 'dnsApi'>('list')
  const owner = certificateOwner(principal, sessionEpoch, targetUser ?? undefined)!
  return (
    <section className="identity-page certificate-page" aria-labelledby="certificate-list-title">
      <CertificateListPageContent
        key={JSON.stringify(owner)}
        owner={owner}
        targetUser={targetUser ? { id: targetUser.id, username: targetUser.username, displayID: targetUser.display_id } : null}
        contextUser={targetUser}
        canManage={canManageCertificatePermission(principal, 'certificates.manage')}
        canReadDNS={canManageCertificatePermission(principal, 'dns.read')}
        canManageDNS={canManageCertificatePermission(principal, 'dns.manage')}
        initialSection={section}
        onSectionChange={setSection}
        targetSelector={(disabled) => <CertificateOwnerPicker owner={owner} value={targetUser} onChange={setTargetUser} disabled={disabled} />}
      />
    </section>
  )
}

function CertificateListPageContent({
  owner, targetUser, contextUser, canManage, canReadDNS, canManageDNS, targetSelector, initialSection = 'list', onSectionChange,
}: {
  owner: CertificateOwner
  targetUser: CertificateTargetUser | null
  /** 平台页已选的用户（默认设置/DNS API 的目标用户），手动申请时默认带入 */
  contextUser?: ManagedUser | null
  canManage: boolean
  canReadDNS: boolean
  canManageDNS: boolean
  targetSelector?: (disabled: boolean) => ReactNode
  initialSection?: 'list' | 'default' | 'dnsApi'
  onSectionChange?: (section: 'list' | 'default' | 'dnsApi') => void
}) {
  const { t, i18n } = useTranslation('certificates')
  const { t: assetT } = useTranslation('certificateAssets')
  const { t: systemT } = useTranslation('systemSettings')
  const sessionPrincipal = useSessionStore((state) => state.principal)
  const { t: dnsT } = useTranslation('dnsProviders')
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const { message, modal } = App.useApp()
  const queryOwner = useRef(owner).current
  // A tenant's certificates are all its own: the 用户 column (and export field) is platform-only.
  const isTenant = queryOwner[0] === 'tenant'
  const targetScopeID = queryOwner[0] === 'platform' ? queryOwner[1] ?? undefined : undefined
  const lineageActiveRef = useRef(true)
  const assetPrefix = useMemo(() => ['certificate-assets', ...queryOwner] as const, [queryOwner])
  const orderPrefix = useMemo(() => ['certificate-orders', ...queryOwner] as const, [queryOwner])
  const providerPrefix = useMemo(() => ['dns-providers', ...queryOwner, 'certificate-order-editor'] as const, [queryOwner])
  const defaultsPrefix = useMemo(() => ['certificate-defaults', ...queryOwner] as const, [queryOwner])
  const providerMutationKey = useMemo(() => ['certificate-dns-provider-write', ...queryOwner] as const, [queryOwner])
  const defaultsMutationKey = useMemo(() => ['certificate-defaults-write', ...queryOwner] as const, [queryOwner])
  const detailPrefix = useMemo(() => ['certificate-asset', ...queryOwner] as const, [queryOwner])
  const bindingPrefix = useMemo(() => ['certificate-asset-bindings', ...queryOwner] as const, [queryOwner])
  const uploadMutationKey = useMemo(() => ['certificate-asset-upload', ...queryOwner] as const, [queryOwner])
  const orderMutationKey = useMemo(() => ['certificate-order-create', ...queryOwner] as const, [queryOwner])
  const commandMutationKey = useMemo(() => ['certificate-asset-command', ...queryOwner] as const, [queryOwner])
  const currentSessionAccess = useCallback((permission: CertificatePermission) => (
    lineageActiveRef.current ? currentCertificateSessionAccess(queryOwner, permission) : null
  ), [queryOwner])
  const currentSessionMatches = useCallback(() => (
    lineageActiveRef.current && currentCertificateSessionMatches(queryOwner)
  ), [queryOwner])
  // 从网站入口（?site=）进来时，目标用户就是网站所属用户，只读显示、不需选择；
  // 手动打开添加/申请时不再沿用。读不到网站（无 sites.read 等）就退回手动选择。
  const siteParamRef = useRef(searchParams.get('site') ?? '')
  const [fromSite, setFromSite] = useState(() => siteParamRef.current !== '' && (searchParams.get('domains') ?? '').trim() !== '')
  const siteOwnerQuery = useQuery({
    queryKey: ['certificate-site-owner', ...queryOwner, siteParamRef.current],
    enabled: queryOwner[0] === 'platform' && fromSite,
    retry: false,
    gcTime: 0,
    queryFn: async () => {
      const token = currentSessionAccess('sites.read')
      if (!token) throw certificatePermissionDenied()
      return sitesApi.detail(token, siteParamRef.current)
    },
  })
  const siteRecord = fromSite ? siteOwnerQuery.data : undefined
  const siteOwner = siteRecord?.scope_id && siteRecord.owner
    ? { scopeID: siteRecord.scope_id, label: siteRecord.owner.display_id ? `${siteRecord.owner.display_name}（ID: ${siteRecord.owner.display_id}）` : siteRecord.owner.display_name }
    : fromSite && siteOwnerQuery.isPending ? { scopeID: undefined, label: assetT('target.loading') } : null
  const [form] = Form.useForm<CertificateForm>()
  const [uploadForm] = Form.useForm<AssetUploadForm>()
  const [batchForm] = Form.useForm<BatchForm>()
	  const [bindForm] = Form.useForm<AssetBindForm>()
  // 'orders' is the 申请记录 view, opened from a row (one certificate's
  // requests) or from 更多操作 (all requests); there is no inner tab.
  const [activeTab, setActiveTab] = useState<'assets' | 'orders'>('assets')
  const [orderAsset, setOrderAsset] = useState<{ id: string; sans: string[] } | null>(null)
  const [sectionTab, setSectionTab] = useState<'list' | 'default' | 'dnsApi'>(initialSection)
  const initialDomainsRef = useRef(searchParams.get('domains') ?? '')
  const initialChallengeRef = useRef<CertificateChallengeType>('dns-01')
  const [editorOpen, setEditorOpen] = useState(() => initialDomainsRef.current.trim().length > 0)
  const [uploadOpen, setUploadOpen] = useState(false)
  // CERT-04 统一“添加证书”弹窗：单个（自己上传=uploadOpen / CA=editorOpen）与批量申请（batchOpen）
  const [batchOpen, setBatchOpen] = useState(false)
  const [batchRows, setBatchRows] = useState<BatchRow[]>([])
  const [batchRunning, setBatchRunning] = useState(false)
  const [selectedIssuer, setSelectedIssuer] = useState<CertificateIssuer>('lets_encrypt')
  const issuerTouchedRef = useRef(false)
  const autoTypeRef = useRef(false)
  const addOpen = uploadOpen || editorOpen || batchOpen
  const [uploadOwner, setUploadOwner] = useState<ManagedUser | null>(null)
  const [orderOwner, setOrderOwner] = useState<ManagedUser | null>(null)
  const [reapplyScopeID, setReapplyScopeID] = useState<string | undefined>()
  const orderScopeID = queryOwner[0] === 'platform' ? reapplyScopeID ?? (siteOwner ? siteOwner.scopeID : orderOwner?.scope_id) : undefined
  const providerScopeID = editorOpen || batchOpen ? orderScopeID : targetScopeID
  const [assetAttempt, setAssetAttempt] = useState<AssetWriteAttempt | null>(null)
  const [assetWriteError, setAssetWriteError] = useState<ApiError | null>(null)
	  const [detail, setDetail] = useState<CertificateAssetDetail | null>(null)
	  const [bindings, setBindings] = useState<CertificateAssetBinding[]>([])
	  const [bindingRevisions, setBindingRevisions] = useState<Record<string, number>>({})
	  const [detailError, setDetailError] = useState<ApiError | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<CertificateAsset | null>(null)
	  const [bindTarget, setBindTarget] = useState<Required<AssetTarget> | null>(null)
	  const [commandAttempt, setCommandAttempt] = useState<AssetCommandAttempt | null>(null)
	  const [commandError, setCommandError] = useState<ApiError | null>(null)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  // The order refusal marked on a form field: the editor shows no alert for it.
  const [orderFieldMarked, setOrderFieldMarked] = useState(false)
  const markOrderError = useFormSubmitError(form, orderErrorMap)
  const [providerEditor, setProviderEditor] = useState<DNSProviderEditorState | null>(null)
  const [providerAttempt, setProviderAttempt] = useState<ProviderWriteAttempt | null>(null)
  const [providerWriteError, setProviderWriteError] = useState<ApiError | null>(null)
  const [defaultType, setDefaultType] = useState<CertificateDefaultType>('acme')
  const [defaultProviderID, setDefaultProviderID] = useState<string | undefined>(undefined)
  const [defaultIssuer, setDefaultIssuer] = useState<CertificateIssuer | undefined>(undefined)
  const [defaultWriteError, setDefaultWriteError] = useState<ApiError | null>(null)
  const [accepted, setAccepted] = useState(false)
  const [reapplyTarget, setReapplyTarget] = useState<{ name: string, input: CreateCertificateOrderInput } | null>(null)
  const [search, setSearch] = useState('')
  const [searchDraft, setSearchDraft] = useState('')
  const applyLiveRef = useRef<(next: CertificateFilterDraft) => void>(() => undefined)
  const [assetFilter, setAssetFilter] = useState<AssetStatusFilter>('all')
  const [advancedFilterOpen, setAdvancedFilterOpen] = useState(false)
  const [filterDraft, setFilterDraft] = useState<CertificateFilterDraft>({
    domain: '', multiDomain: '', user: '', certificateID: '', name: '', remark: '',
  })
  const [appliedFilters, setAppliedFilters] = useState<CertificateFilterDraft>({
    domain: '', multiDomain: '', user: '', certificateID: '', name: '', remark: '',
  })
  const [selectedAssetIDs, setSelectedAssetIDs] = useState<string[]>([])
  const [selectedProviderIDs, setSelectedProviderIDs] = useState<string[]>([])
  const [providerPage, setProviderPage] = useState(1)
  const [providerLimit, setProviderLimit] = useState(10)
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
	const assetSearch = search.trim()
	// Status pills filter on the server (counts cover every page).
	const assetStatus = assetFilter === 'all' ? undefined : assetStatusQuery[assetFilter]
	const assetFilters = useMemo(() => serverAssetFilters(appliedFilters), [appliedFilters])
	const hasAssetFilters = Object.values(assetFilters).some((value) => value !== undefined)
	const assetFiltersKey = hasAssetFilters ? JSON.stringify(assetFilters) : ''
	const assetQueryKey = useMemo(
		() => [...assetPrefix, page, limit, assetSearch, assetStatus ?? '', ...(assetFiltersKey ? [assetFiltersKey] : [])] as const,
		[assetFiltersKey, assetPrefix, assetSearch, assetStatus, limit, page],
	)
  const challenge = Form.useWatch('challenge_type', form) ?? 'dns-01'

  const uploadAttemptRef = useRef<AssetWriteAttempt | null>(null)
  const commandAttemptRef = useRef<AssetCommandAttempt | null>(null)
  const orderAttemptRef = useRef<WriteAttempt | null>(null)
  const providerAttemptRef = useRef<ProviderWriteAttempt | null>(null)
  const defaultsAttemptRef = useRef<CertificateDefaultsAttempt | null>(null)

  useEffect(() => {
    lineageActiveRef.current = true
    const cleanupOwnerCache = () => {
      queryClient.removeQueries({ queryKey: assetPrefix })
      queryClient.removeQueries({ queryKey: orderPrefix })
      queryClient.removeQueries({ queryKey: providerPrefix })
      queryClient.removeQueries({ queryKey: defaultsPrefix })
      queryClient.removeQueries({ queryKey: detailPrefix })
      queryClient.removeQueries({ queryKey: bindingPrefix })
      queryClient.removeQueries({ queryKey: ['certificate-issuers', ...queryOwner] })
      const mutationCache = queryClient.getMutationCache()
      for (const key of [uploadMutationKey, orderMutationKey, commandMutationKey, providerMutationKey, defaultsMutationKey]) {
        for (const mutation of mutationCache.findAll({ mutationKey: key, exact: true })) mutationCache.remove(mutation)
      }
    }
    return () => {
      lineageActiveRef.current = false
      clearProviderWriteCredentials(providerAttemptRef.current)
      providerAttemptRef.current = null
      uploadForm.resetFields()
      if (!currentCertificateSessionMatches(queryOwner)) {
        cleanupOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) cleanupOwnerCache()
      })
    }
  }, [assetPrefix, bindingPrefix, commandMutationKey, defaultsMutationKey, defaultsPrefix, detailPrefix, orderMutationKey, orderPrefix, providerMutationKey, providerPrefix, queryClient, queryOwner, uploadForm, uploadMutationKey])

  const assetsQuery = useQuery({
	queryKey: assetQueryKey,
	enabled: sectionTab === 'list',
    queryFn: async () => {
      const token = currentSessionAccess('certificates.read')
      if (!token) throw certificatePermissionDenied()
      try {
		const value = await certificatesApi.listAssets(token, undefined, {
			page, limit, search: assetSearch, status: assetStatus, ...(hasAssetFilters ? { filters: assetFilters } : {}),
		})
        if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
        for (const asset of value.items) assertAssetOwner(queryOwner, asset)
        return value
      } catch (error) {
        if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
        throw error
      }
    },
  })

  const query = useQuery({
    queryKey: orderPrefix,
    queryFn: async () => {
      const token = currentSessionAccess('certificates.read')
      if (!token) throw certificatePermissionDenied()
      try {
        const value = await certificatesApi.list(token)
        if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
        const items = value.items
        for (const order of items) assertOrderOwner(queryOwner, order)
        return { items }
      } catch (error) {
        if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
        throw error
      }
    },
    enabled: sectionTab === 'list',
  })
  const assetPageItems = useMemo(() => assetsQuery.data?.items ?? [], [assetsQuery.data?.items])
  const assetDetailQueries = useQueries({
    queries: assetPageItems.map((asset) => ({
      queryKey: [...detailPrefix, asset.id, 'list-projection'] as const,
      enabled: sectionTab === 'list' && activeTab === 'assets',
      retry: false,
      queryFn: async () => {
        const token = currentSessionAccess('certificates.read')
        if (!token) throw certificatePermissionDenied()
        try {
          const value = await certificatesApi.getAsset(token, asset.id, queryOwner[0] === 'platform' ? asset.tenant_scope_id : undefined)
          if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
          assertAssetDetail(queryOwner, value, asset.id, asset.tenant_scope_id)
          return value
        } catch (error) {
          if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
          throw error
        }
      },
    })),
  })
  const providersQuery = useQuery({
    queryKey: queryOwner[0] === 'platform' ? [...providerPrefix, providerScopeID] : providerPrefix,
    queryFn: async () => {
      const token = currentSessionAccess('dns.read')
      if (!token) throw certificatePermissionDenied()
      try {
        const value = await dnsApi.list(token)
        if (!currentSessionAccess('dns.read')) throw invalidCertificateResponse()
        const items = queryOwner[0] === 'platform'
          ? value.items.filter((provider) => provider.scope_id === providerScopeID)
          : value.items
        for (const provider of items) assertProviderOwner(queryOwner, provider, providerScopeID ?? queryOwner[1])
        return { ...value, items }
      } catch (error) {
        if (!currentSessionAccess('dns.read')) throw invalidCertificateResponse()
        throw error
      }
    },
    enabled: (editorOpen || batchOpen || advancedFilterOpen || sectionTab === 'default' || sectionTab === 'dnsApi') && canReadDNS &&
      (queryOwner[0] === 'tenant' || Boolean(providerScopeID)),
  })

  // CERT-04：可选签发机构只列平台已配置的 CA；只有一个（仅 Let's Encrypt）时不显示选择。
  const issuersQuery = useQuery({
    queryKey: ['certificate-issuers', ...queryOwner],
    enabled: addOpen || sectionTab === 'default',
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      const token = currentSessionAccess('certificates.read')
      if (!token) throw certificatePermissionDenied()
      return certificatesApi.listIssuers(token)
    },
  })
  const issuerOptions = (issuersQuery.data?.items ?? []).map((issuer) => ({
    value: issuer,
    label: t(`issuers.${issuer}`) + (issuer === issuersQuery.data?.default ? t('issuers.platformDefault') : ''),
  }))
  const defaultsQuery = useQuery({
    queryKey: defaultsPrefix,
    retry: false,
    queryFn: async () => {
      const token = currentSessionAccess('certificates.read')
      if (!token || !targetUser) throw certificatePermissionDenied()
      const value = await certificatesApi.getDefaults(token, targetScopeID, targetUser.id)
      if (!currentSessionAccess('certificates.read') || value.scope_id !== queryOwner[1] || value.user_id !== targetUser.id) {
        throw invalidCertificateResponse()
      }
      return value
    },
    // CERT-03：租户新申请也读本人默认，带入默认 DNS 账号
    enabled: (sectionTab === 'default' || (addOpen && isTenant)) && Boolean(targetUser),
  })

  // CERT-03：新增流程只按一个确定的 (scope,user) 读默认：租户是本人（defaultsQuery），
  // 平台管理员是弹窗里选的归属/目标用户或网站带入的网站所有者，不是设置页选的用户。
  const addTarget = useMemo(() => {
    if (isTenant || reapplyScopeID) return null
    if (siteOwner && !uploadOpen) {
      return siteRecord?.scope_id && siteRecord.owner ? { scopeID: siteRecord.scope_id, userID: siteRecord.owner.id } : null
    }
    const picked = uploadOpen ? uploadOwner : orderOwner
    return picked ? { scopeID: picked.scope_id, userID: picked.id } : null
  }, [isTenant, orderOwner, reapplyScopeID, siteOwner, siteRecord, uploadOpen, uploadOwner])
  const addTargetKey = addTarget ? `${addTarget.scopeID}/${addTarget.userID}` : ''
  const addTargetDefaultsQuery = useQuery({
    queryKey: [...defaultsPrefix, 'add-target', addTarget?.scopeID, addTarget?.userID],
    retry: false,
    queryFn: async () => {
      const token = currentSessionAccess('certificates.read')
      if (!token || !addTarget) throw certificatePermissionDenied()
      const value = await certificatesApi.getDefaults(token, addTarget.scopeID, addTarget.userID)
      if (!currentSessionAccess('certificates.read') || value.scope_id !== addTarget.scopeID || value.user_id !== addTarget.userID) {
        throw invalidCertificateResponse()
      }
      return value
    },
    enabled: addOpen && Boolean(addTarget),
  })
  const addDefaults = isTenant ? defaultsQuery.data : addTarget ? addTargetDefaultsQuery.data : undefined

  useEffect(() => {
    if (!defaultsQuery.data) return
    setDefaultType(defaultsQuery.data.certificate_type)
    setDefaultProviderID(defaultsQuery.data.dns_provider_id)
    setDefaultIssuer(defaultsQuery.data.issuer)
    setDefaultWriteError(null)
  }, [defaultsQuery.data])

  // 切换证书类型时带过去的名称/备注（两个表单各自独立校验）
  const carryRef = useRef<{ name?: string; remark?: string } | null>(null)
  useEffect(() => {
    if (!editorOpen) return
    const initialDomains = initialDomainsRef.current
    const initialChallenge = initialChallengeRef.current
    form.resetFields()
    form.setFieldsValue({ domains_text: initialDomains, challenge_type: initialChallenge, auto_renew: true, ...carryRef.current })
    carryRef.current = null
    initialDomainsRef.current = ''
    initialChallengeRef.current = 'dns-01'
    defaultProviderAppliedRef.current = null
  }, [editorOpen, form])

  // CERT-03：打开申请弹窗后，用户还没选 DNS 账号时带入目标用户的默认 DNS 账号；默认账号已
  // 删除或停用就不带入（仍需用户选择）。每个目标只带入一次，用户改选后不再覆盖；换目标重新带入。
  const defaultProviderAppliedRef = useRef<string | null>(null)
  useEffect(() => {
    const applied = isTenant ? 'self' : addTargetKey
    if (!editorOpen || !applied || defaultProviderAppliedRef.current === applied || !addDefaults || !providersQuery.data) return
    if (!isTenant && providersQuery.data.items.some((item) => item.scope_id !== addTarget?.scopeID)) return
    defaultProviderAppliedRef.current = applied
    const providerID = addDefaults.certificate_type === 'acme' ? addDefaults.dns_provider_id : undefined
    if (!providerID || form.getFieldValue('dns_provider_id')) return
    if (providersQuery.data.items.some((item) => item.id === providerID && item.status !== 'disabled' &&
      (!isTenant || item.managed_by !== 'platform'))) {
      form.setFieldValue('dns_provider_id', providerID)
    }
  }, [editorOpen, isTenant, addDefaults, addTarget?.scopeID, addTargetKey, providersQuery.data, form])

  useEffect(() => {
    if (!uploadOpen || !carryRef.current) return
    uploadForm.setFieldsValue(carryRef.current)
    carryRef.current = null
  }, [uploadOpen, uploadForm])

  // 打开时预选签发机构：本人默认（平台已配置时）> 平台默认 > 第一个可用；用户点选后不再覆盖。
  const offeredIssuers = useMemo(() => {
    const items = issuersQuery.data?.items ?? []
    return issuerCardOrder.filter((issuer) => items.includes(issuer))
  }, [issuersQuery.data?.items])
  useEffect(() => {
    if (!addOpen || issuerTouchedRef.current || offeredIssuers.length === 0) return
    const preferred = [addDefaults?.issuer, issuersQuery.data?.default]
      .find((issuer): issuer is CertificateIssuer => issuer !== undefined && offeredIssuers.includes(issuer))
    setSelectedIssuer(preferred ?? offeredIssuers[0])
  }, [addOpen, addDefaults?.issuer, issuersQuery.data?.default, offeredIssuers])

	  useEffect(() => {
		if (!bindTarget) return
		bindForm.resetFields()
		bindForm.setFieldsValue({ site_id: '', version_id: bindTarget.version.id, default: false })
	  }, [bindForm, bindTarget])

  const uploadMutation = useMutation<void, unknown, void>({
    mutationKey: uploadMutationKey,
    mutationFn: async () => {
      const frozen = uploadAttemptRef.current
      const token = currentSessionAccess('certificates.manage')
      if (!frozen || !token) throw certificatePermissionDenied()
      const value = await certificatesApi.uploadAsset(token, frozen.input, frozen.key, frozen.requestID, frozen.targetScopeID)
      if (!currentSessionMatches()) throw invalidCertificateResponse()
      assertAssetDetail(queryOwner, value, undefined, frozen.targetScopeID ?? queryOwner[1] ?? undefined)
      if (value.asset.name !== frozen.input.name ||
        (frozen.targetTenantID && value.asset.tenant.id !== frozen.targetTenantID) ||
        (frozen.input.owner_user_id && (value.asset.owner_status !== 'recorded' || value.asset.owner?.id !== frozen.input.owner_user_id)) ||
        !value.versions.some((version) => samePEMCertificateChain(version.certificate_pem, frozen.input.certificate_pem))) {
        throw invalidCertificateResponse()
      }
    },
    onSuccess: async () => {
      if (!currentSessionMatches()) return
      uploadAttemptRef.current = null
      setAssetAttempt(null)
      setAssetWriteError(null)
      setUploadOpen(false)
      uploadForm.resetFields()
      setUploadOwner(null)
      await queryClient.invalidateQueries({ queryKey: assetPrefix })
    },
    onError: (error: unknown) => {
      if (!currentSessionMatches()) return
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setAssetWriteError(apiError)
      if (!outcomeUnknown(error)) {
        uploadAttemptRef.current = null
        setAssetAttempt(null)
      }
    },
  })

	  const commandMutation = useMutation<void, unknown, void>({
		mutationKey: commandMutationKey,
		mutationFn: async () => {
		  const frozen = commandAttemptRef.current
		  const token = currentSessionAccess('certificates.manage')
		  if (!frozen || !token) throw certificatePermissionDenied()
		  const asset = 'target' in frozen ? frozen.target.asset : frozen.asset
		  const commandScopeID = queryOwner[0] === 'platform' ? asset.tenant_scope_id : undefined
		  switch (frozen.kind) {
			case 'activate': {
			  const value = await certificatesApi.activateAssetVersion(
				token, frozen.target.asset.id, frozen.target.version.id,
				{ expected_revision: frozen.target.asset.revision }, frozen.key, frozen.requestID, commandScopeID,
			  )
			  if (!currentSessionMatches() || value.tenant_scope_id !== asset.tenant_scope_id ||
				value.asset_id !== frozen.target.asset.id || value.id !== frozen.target.version.id ||
				value.status !== 'active') {
				throw invalidCertificateResponse()
			  }
			  break
			}
			case 'delete': {
			  const value = await certificatesApi.deleteAsset(
				token, frozen.asset.id, { expected_revision: frozen.asset.revision }, frozen.key, frozen.requestID, commandScopeID,
			  )
			  if (!currentSessionMatches()) throw invalidCertificateResponse()
			  assertAssetOwner(queryOwner, value, frozen.asset.id, asset.tenant_scope_id)
			  if (!value.deleted_at) throw invalidCertificateResponse()
			  break
			}
			case 'bind': {
			  const value = await certificatesApi.bindAsset(token, frozen.target.asset.id, frozen.input, frozen.key, frozen.requestID, commandScopeID)
			  if (!currentSessionMatches()) throw invalidCertificateResponse()
			  assertBinding(queryOwner, value, frozen.target.asset.id, new Set([frozen.input.version_id]), frozen.input.site_id, asset.tenant_scope_id)
			  if (!value.bound || value.default !== frozen.input.default) throw invalidCertificateResponse()
			  break
			}
			case 'unbind': {
			  const value = await certificatesApi.unbindAsset(
				token, frozen.asset.id, frozen.binding.site_id,
				{ expected_revision: frozen.binding.revision }, frozen.key, frozen.requestID, commandScopeID,
			  )
			  if (!currentSessionMatches()) throw invalidCertificateResponse()
			  assertBinding(queryOwner, value, frozen.asset.id, new Set([frozen.binding.version_id]), frozen.binding.site_id, asset.tenant_scope_id)
			  if (value.bound) throw invalidCertificateResponse()
			}
		  }
		},
		onSuccess: () => {
		  if (!currentSessionMatches()) return
		  commandAttemptRef.current = null
		  setCommandAttempt(null)
		  setCommandError(null)
		  setDetail(null)
		  setBindings([])
		  setDeleteTarget(null)
		  setBindTarget(null)
		  void queryClient.invalidateQueries({ queryKey: assetPrefix })
		},
		onError: (error: unknown) => {
		  if (!currentSessionMatches()) return
		  const apiError = error instanceof ApiError ? error : new ApiError('request failed')
		  setCommandError(apiError)
		  if (!outcomeUnknown(error)) {
			commandAttemptRef.current = null
			setCommandAttempt(null)
		  }
		},
	  })

	  // 列表里直接开关自动续签（资产层，迁移 540）。点击后先显示新状态并 loading，
	  // 失败回滚并提示原因；成功刷新列表与顶部计数。
	  const [autoRenewPending, setAutoRenewPending] = useState<Record<string, boolean>>({})
	  const autoRenewMutation = useMutation<CertificateAsset, unknown, { asset: CertificateAsset; enabled: boolean }>({
		mutationFn: async ({ asset, enabled }) => {
		  const token = currentSessionAccess('certificates.manage')
		  if (!token) throw certificatePermissionDenied()
		  const scopeID = queryOwner[0] === 'platform' ? asset.tenant_scope_id : undefined
		  const value = await certificatesApi.setAssetAutoRenew(token, asset.id,
			{ enabled, expected_revision: asset.revision }, requestID(), requestID(), scopeID)
		  if (!currentSessionMatches()) throw invalidCertificateResponse()
		  assertAssetOwner(queryOwner, value, asset.id, asset.tenant_scope_id)
		  return value
		},
		onMutate: ({ asset, enabled }) => setAutoRenewPending((current) => ({ ...current, [asset.id]: enabled })),
		onSuccess: (value) => {
		  message.success(assetT(value.auto_renew ? 'autoRenew.enabled' : 'autoRenew.disabled'))
		},
		onError: (error: unknown) => {
		  const apiError = error instanceof ApiError ? error : new ApiError('request failed')
		  message.error(assetT('autoRenew.failed', { reason: errorMessage(apiError, t) }))
		},
		onSettled: async (_value, _error, { asset }) => {
		  await queryClient.invalidateQueries({ queryKey: assetPrefix })
		  setAutoRenewPending((current) => {
			const next = { ...current }
			delete next[asset.id]
			return next
		  })
		},
	  })

	  // 更多 > 禁用/启用/下载证书；表头 更多操作 只放批量动作。
	  const assetScopeID = (asset: CertificateAsset) => queryOwner[0] === 'platform' ? asset.tenant_scope_id : undefined
	  const certOpError = (error: unknown) => {
		const apiError = error instanceof ApiError ? error : new ApiError('request failed')
		return apiError.code === 'certificate_asset_referenced' ? assetT('certOps.boundCannotDisable') : errorMessage(apiError, assetT)
	  }
	  const disabledMutation = useMutation<CertificateAsset, unknown, { asset: CertificateAsset; disabled: boolean }>({
		mutationFn: async ({ asset, disabled }) => {
		  const token = currentSessionAccess('certificates.manage')
		  if (!token) throw certificatePermissionDenied()
		  const value = await certificatesApi.setAssetDisabled(token, asset.id,
			{ disabled, expected_revision: asset.revision }, requestID(), requestID(), assetScopeID(asset))
		  if (!currentSessionMatches()) throw invalidCertificateResponse()
		  assertAssetOwner(queryOwner, value, asset.id, asset.tenant_scope_id)
		  return value
		},
		onSuccess: (value) => { message.success(assetT(value.disabled ? 'certOps.disabledDone' : 'certOps.enabledDone')) },
		onError: (error) => { message.error(assetT('certOps.toggleFailed', { reason: certOpError(error) })) },
		onSettled: async () => { await queryClient.invalidateQueries({ queryKey: assetPrefix }) },
	  })
	  const downloadCertificate = async (token: string, asset: CertificateAsset) => {
		const { blob, filename } = await certificatesApi.downloadAsset(token, asset.id, requestID(), assetScopeID(asset))
		const url = URL.createObjectURL(blob)
		const link = document.createElement('a')
		link.href = url
		link.download = filename
		link.rel = 'noopener'
		document.body.appendChild(link)
		link.click()
		link.remove()
		URL.revokeObjectURL(url)
	  }
	  const downloadMutation = useMutation<void, unknown, CertificateAsset>({
		mutationFn: async (asset) => {
		  const token = currentSessionAccess('certificates.manage')
		  if (!token) throw certificatePermissionDenied()
		  await downloadCertificate(token, asset)
		},
		onSuccess: () => { message.success(assetT('certOps.downloaded')) },
		onError: (error) => {
		  const apiError = error instanceof ApiError ? error : new ApiError('request failed')
		  message.error(apiError.code === 'certificate_asset_download_unavailable'
			? assetT('certOps.downloadRevoked') : assetT('certOps.downloadFailed', { reason: errorMessage(apiError, assetT) }))
		},
	  })
	  // 批量：逐张调用单张接口（部分失败时汇总提示）。
	  const bulkMutation = useMutation<{ done: number; failed: number; reason: string }, unknown, { action: BulkAction; assets: CertificateAsset[] }>({
		mutationFn: async ({ action, assets }) => {
		  const token = currentSessionAccess('certificates.manage')
		  if (!token) throw certificatePermissionDenied()
		  let done = 0, failed = 0, reason = ''
		  for (const asset of assets) {
			try {
			  if (action === 'download') await downloadCertificate(token, asset)
			  else if (action === 'delete') {
				await certificatesApi.deleteAsset(token, asset.id, { expected_revision: asset.revision }, requestID(), requestID(), assetScopeID(asset))
			  } else if (action === 'enable' || action === 'disable') {
				await certificatesApi.setAssetDisabled(token, asset.id, { disabled: action === 'disable', expected_revision: asset.revision },
				  requestID(), requestID(), assetScopeID(asset))
			  } else {
				await certificatesApi.setAssetAutoRenew(token, asset.id, { enabled: action === 'enableAutoRenew', expected_revision: asset.revision },
				  requestID(), requestID(), assetScopeID(asset))
			  }
			  done += 1
			} catch (error) {
			  failed += 1
			  if (!reason) reason = certOpError(error)
			}
		  }
		  return { done, failed, reason }
		},
		onSuccess: ({ done, failed, reason }, { action }) => {
		  if (action === 'delete') setSelectedAssetIDs([])
		  if (failed === 0) message.success(assetT('certOps.bulkDone', { done }))
		  else message.warning(assetT('certOps.bulkPartial', { done, failed, reason }))
		},
		onError: (error) => { message.error(assetT('certOps.toggleFailed', { reason: certOpError(error) })) },
		onSettled: async () => { await queryClient.invalidateQueries({ queryKey: assetPrefix }) },
	  })

	  const loadDetail = async (asset: CertificateAsset) => {
		const token = currentSessionAccess('certificates.read')
		if (!token) return
		setDetailLoading(true)
		setDetailError(null)
		setCommandError(null)
		try {
		  const detailScopeID = queryOwner[0] === 'platform' ? asset.tenant_scope_id : undefined
		  const [value, bindingList] = await Promise.all([
			certificatesApi.getAsset(token, asset.id, detailScopeID),
			certificatesApi.listAssetBindings(token, asset.id, detailScopeID),
		  ])
		  if (!currentSessionAccess('certificates.read')) throw invalidCertificateResponse()
		  assertAssetDetail(queryOwner, value, asset.id, asset.tenant_scope_id)
		  const versionIDs = new Set(value.versions.map((version) => version.id))
		  for (const binding of bindingList.items) assertBinding(queryOwner, binding, asset.id, versionIDs, undefined, asset.tenant_scope_id)
		  queryClient.setQueryData([...detailPrefix, asset.id], value)
		  queryClient.setQueryData([...bindingPrefix, asset.id], bindingList)
		  setBindingRevisions(Object.fromEntries(bindingList.items.map((binding) => [binding.site_id, binding.revision])))
		  setDetail(value)
		  setBindings(bindingList.items.filter((binding) => binding.bound))
		} catch (error) {
		  if (currentSessionMatches()) setDetailError(error instanceof ApiError ? error : new ApiError('request failed'))
		} finally {
      if (currentSessionMatches()) setDetailLoading(false)
    }
  }

  const mutation = useMutation<CertificateOrder, unknown, void>({
    mutationKey: orderMutationKey,
    mutationFn: async () => {
      const frozen = orderAttemptRef.current
      const token = currentSessionAccess('certificates.manage')
      if (!frozen || !token || (frozen.input.dns_provider_id && !currentSessionAccess('dns.read'))) {
        throw certificatePermissionDenied()
      }
      let value: CertificateOrder
      try {
        value = await certificatesApi.create(token, frozen.input, frozen.key)
      } catch (error) {
        if (!orderServerFailure(error) || !currentSessionMatches()) throw error
        // Look the order up by its Idempotency-Key: the replay is the real result.
        value = await certificatesApi.create(token, frozen.input, frozen.key)
      }
      if (!currentSessionMatches()) throw invalidCertificateResponse()
      assertOrderOwner(queryOwner, value, frozen.input.target_scope_id)
      if (!orderReceiptMatches(value, frozen.input)) throw invalidCertificateResponse()
      return value
    },
    onSuccess: async (order) => {
      if (!currentSessionMatches()) return
      // 受理的申请立刻进申请记录缓存，行状态马上显示“申请中”，不等列表重拉。
      queryClient.setQueryData<{ items: CertificateOrder[] }>(orderPrefix, (current) => current
        ? { items: [order, ...current.items.filter((item) => item.id !== order.id)] }
        : current)
      // 重新申请只弹 toast；新申请仍显示页内“证书申请已提交”。
      if (reapplyTarget) message.success(assetT('reapply.submitted'))
      else if (currentSessionAccess('certificates.manage')) setAccepted(true)
      orderAttemptRef.current = null
      setAttempt(null)
      setWriteError(null)
      setEditorOpen(false)
      setReapplyTarget(null)
      form.resetFields()
      await queryClient.invalidateQueries({ queryKey: orderPrefix })
    },
    onError: (error: unknown) => {
      if (!currentSessionMatches()) return
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      // A server failure keeps the attempt unlocked: submitting the same
      // request again reuses its Idempotency-Key (orderAttemptFor).
      if (!outcomeUnknown(error)) {
        orderAttemptRef.current = null
        setAttempt(null)
      }
      setOrderFieldMarked(!outcomeUnknown(error) && markOrderError(error))
    },
  })
  const orderAttemptFor = (input: CreateCertificateOrderInput): WriteAttempt => {
    const previous = orderAttemptRef.current
    return previous && JSON.stringify(previous.input) === JSON.stringify(input) ? previous : { input, key: writeKey() }
  }

  const providerMutation = useMutation<void, unknown, void>({
    mutationKey: providerMutationKey,
    mutationFn: async () => {
      const frozen = providerAttemptRef.current
      const token = currentSessionAccess('dns.manage')
      if (!frozen || !token) throw certificatePermissionDenied()
      switch (frozen.kind) {
        case 'create': {
          const value = await dnsApi.create(token, frozen.input, frozen.key)
          if (!currentSessionMatches()) throw invalidCertificateResponse()
          assertProviderOwner(queryOwner, value)
          break
        }
        case 'update': {
          const value = await dnsApi.update(token, frozen.id, frozen.providerType, frozen.input, frozen.key)
          if (!currentSessionMatches() || value.id !== frozen.id) throw invalidCertificateResponse()
          assertProviderOwner(queryOwner, value)
          break
        }
        case 'verify': {
          const value = await dnsApi.verify(token, frozen.id, frozen.providerType, frozen.version, frozen.key)
          if (!currentSessionMatches() || value.id !== frozen.id || value.status !== 'verified') throw invalidCertificateResponse()
          assertProviderOwner(queryOwner, value)
          break
        }
        case 'delete':
          await dnsApi.remove(token, frozen.id, frozen.version, frozen.key)
          if (!currentSessionMatches()) throw invalidCertificateResponse()
          break
      }
    },
    onSuccess: async () => {
      if (!currentSessionMatches()) return
      clearProviderWriteCredentials(providerAttemptRef.current)
      providerAttemptRef.current = null
      setProviderAttempt(null)
      setProviderWriteError(null)
      setProviderEditor(null)
      await queryClient.invalidateQueries({ queryKey: providerPrefix })
    },
    onError: (error: unknown) => {
      if (!currentSessionMatches()) return
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setProviderWriteError(apiError)
      if (!outcomeUnknown(error)) {
        clearProviderWriteCredentials(providerAttemptRef.current)
        providerAttemptRef.current = null
        setProviderAttempt(null)
        if (apiError.code === 'version_conflict' || apiError.code === 'dns_resource_not_found') {
          setProviderEditor(null)
          void providersQuery.refetch()
        }
      }
    },
  })

  const defaultsMutation = useMutation<void, unknown, void>({
    mutationKey: defaultsMutationKey,
    mutationFn: async () => {
      const frozen = defaultsAttemptRef.current
      const token = currentSessionAccess('certificates.manage')
      if (!frozen || !token) throw certificatePermissionDenied()
      const value = await certificatesApi.updateDefaults(token, frozen.input, frozen.key)
      if (!currentSessionMatches() || value.scope_id !== queryOwner[1] || value.user_id !== frozen.input.target_user_id ||
        value.certificate_type !== frozen.input.certificate_type || value.dns_provider_id !== frozen.input.dns_provider_id) {
        throw invalidCertificateResponse()
      }
    },
    onSuccess: async () => {
      if (!currentSessionMatches()) return
      defaultsAttemptRef.current = null
      setDefaultWriteError(null)
      await queryClient.invalidateQueries({ queryKey: defaultsPrefix })
    },
    onError: (error: unknown) => {
      if (!currentSessionMatches()) return
      setDefaultWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
      if (error instanceof ApiError && error.code === 'version_conflict') void defaultsQuery.refetch()
      if (!outcomeUnknown(error)) defaultsAttemptRef.current = null
    },
  })

  const uncertain = Boolean(attempt && writeError && orderOutcomeUnknown(writeError))
  const writesLocked = mutation.isPending || uncertain
  const providerUncertain = Boolean(providerAttempt && providerWriteError && outcomeUnknown(providerWriteError))
  const providerWritesLocked = providerMutation.isPending || providerUncertain
	  // CERT-08：结果未知时冻结输入，只能用原请求重试
	  const defaultsUncertain = Boolean(defaultWriteError && outcomeUnknown(defaultWriteError) && defaultsAttemptRef.current)
	  const defaultsLocked = defaultsMutation.isPending || defaultsUncertain
  // A refused default field (certificate_type / issuer /
  // dns_provider_id) is shown under its select instead of the dialog, until
  // that select changes.
  const refusedDefault = submitErrorFields(defaultWriteError).find((item) => defaultFieldNames.has(item.field))
  const defaultFieldStatus = (field: string) => refusedDefault?.field === field ? 'error' as const : undefined
  const reasonLocale = i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn'
  const defaultFieldHelp = (field: string) => refusedDefault?.field === field
    ? <div className="certificate-default-error" role="alert">{fieldReasonText(refusedDefault.reason, reasonLocale)}</div>
    : null
  const editDefault = () => { if (refusedDefault) setDefaultWriteError(null) }
	  const assetUncertain = Boolean(assetAttempt && assetWriteError && outcomeUnknown(assetWriteError))
	  const assetWritesLocked = uploadMutation.isPending || assetUncertain
  const addLocked = batchRunning || writesLocked || assetWritesLocked
	  const commandUncertain = Boolean(commandAttempt && commandError && outcomeUnknown(commandError))
	  const commandLocked = commandMutation.isPending || commandUncertain

  useEffect(() => {
    if (!canManage) {
      setAccepted(false)
      setUploadOpen(false)
      setEditorOpen(false)
      setBatchOpen(false)
      setDeleteTarget(null)
      setBindTarget(null)
      form.resetFields()
      uploadForm.resetFields()
      bindForm.resetFields()
      return
    }
    if (assetAttempt && assetWriteError && outcomeUnknown(assetWriteError)) setUploadOpen(true)
    if (attempt && writeError && orderOutcomeUnknown(writeError) && !reapplyTarget) setEditorOpen(true)
    if (commandAttempt && commandError && outcomeUnknown(commandError)) {
      if (commandAttempt.kind === 'delete') setDeleteTarget(commandAttempt.asset)
		  if (commandAttempt.kind === 'bind') setBindTarget(commandAttempt.target)
    }
  }, [assetAttempt, assetWriteError, attempt, bindForm, canManage, commandAttempt, commandError, form, reapplyTarget, uploadForm, writeError])

  useEffect(() => {
    if (canManageDNS) return
    clearProviderWriteCredentials(providerAttemptRef.current)
    providerAttemptRef.current = null
    setProviderAttempt(null)
    setProviderWriteError(null)
    setProviderEditor(null)
  }, [canManageDNS])

  useEffect(() => {
    setSelectedProviderIDs([])
    setProviderPage(1)
  }, [queryOwner[1]])

	  const startCommand = (next: AssetCommandAttempt) => {
		if (!currentSessionAccess('certificates.manage')) return
		commandAttemptRef.current = next
		setCommandAttempt(next)
		setCommandError(null)
		commandMutation.mutate()
	  }

	  const closeCommandAndRefresh = () => {
		commandAttemptRef.current = null
		setCommandAttempt(null)
		setCommandError(null)
		setDetail(null)
		setBindings([])
		setDeleteTarget(null)
		setBindTarget(null)
		if (currentSessionAccess('certificates.read')) void assetsQuery.refetch()
	  }

	  const commandAlert = canManage && commandError ? (
		(commandUncertain ? <OutcomeUnknown title={assetT('commandUncertainty.title')} detail={assetT('commandUncertainty.description')} action={<Space size={4}>
			{commandAttempt && (commandAttempt.kind === 'activate' || commandAttempt.kind === 'unbind') ? (
			  <Button size="small" onClick={() => {
				if (currentSessionAccess('certificates.manage')) commandMutation.mutate()
			  }}>{assetT('actions.retrySameRequest')}</Button>
			) : null}
			<Button size="small" onClick={closeCommandAndRefresh}>{assetT('actions.closeAndRefresh')}</Button>
		  </Space>} className="identity-alert" /> : <FeedbackWhen title={errorMessage(commandError, assetT)} />)
	  ) : null

	  const submitUpload = (values: AssetUploadForm) => {
    if (!currentSessionAccess('certificates.manage')) return
    if (queryOwner[0] === 'platform' && (!uploadOwner || uploadOwner.status !== 'active')) {
      setAssetWriteError(new ApiError('owner required', 422, 'certificate_asset_owner_required'))
      return
    }
    const input: ImportCertificateAssetInput = {
      name: values.name.trim(), certificate_pem: values.certificate_pem, private_key_pem: values.private_key_pem,
      ...(values.remark?.trim() ? { remark: values.remark.trim() } : {}),
      ...(queryOwner[0] === 'platform' && uploadOwner ? { owner_user_id: uploadOwner.id } : {}),
    }
    const next = {
      input, key: writeKey(), requestID: requestID(),
      ...(queryOwner[0] === 'platform' ? { targetScopeID: uploadOwner!.scope_id, targetTenantID: uploadOwner!.tenant_id } : {}),
    }
    uploadAttemptRef.current = next
    setAssetAttempt(next)
    setAssetWriteError(null)
		uploadMutation.mutate()
	  }

	  const openBind = () => {
		if (!detail || !currentSessionAccess('certificates.manage')) return
		const version = detail.versions.find((item) => item.status === 'active')
		if (!version) {
		  setDetailError(new ApiError('invalid transition', 409, 'certificate_asset_invalid_transition'))
		  return
		}
		setCommandError(null)
		setBindTarget({ asset: detail.asset, version })
		setDetail(null)
	  }

	  const submitBind = (values: AssetBindForm) => {
		if (!bindTarget || !currentSessionAccess('certificates.manage')) return
		startCommand({
		  kind: 'bind', target: bindTarget,
		  input: {
			site_id: values.site_id, version_id: values.version_id,
			expected_revision: bindingRevisions[values.site_id] ?? 0, default: values.default,
		  },
		  key: writeKey(), requestID: requestID(),
		})
	  }

	  const activateVersion = (version: CertificateAssetVersion) => {
		if (!detail || !currentSessionAccess('certificates.manage')) return
		startCommand({
		  kind: 'activate', target: { asset: detail.asset, version }, key: writeKey(), requestID: requestID(),
		})
	  }

		  const unbind = (binding: CertificateAssetBinding) => {
			if (!detail || !currentSessionAccess('certificates.manage')) return
			startCommand({ kind: 'unbind', asset: detail.asset, binding, key: writeKey(), requestID: requestID() })
		  }

  const startProviderWrite = (next: ProviderWriteIntent) => {
    if (!currentSessionAccess('dns.manage')) return
    clearProviderWriteCredentials(providerAttemptRef.current)
    const value: ProviderWriteAttempt = { ...next, key: providerWriteKey(next.kind) }
    providerAttemptRef.current = value
    setProviderAttempt(value)
    setProviderWriteError(null)
    providerMutation.mutate()
  }

  const submitProviderEditor = (values: ProviderForm) => {
    if (!providerEditor || !currentSessionAccess('dns.manage') || (queryOwner[0] === 'platform' && !targetScopeID)) return
    if (providerEditor.mode === 'create') {
      if (!isCreatableProviderType(values.provider_type)) return
      const credentials = Object.fromEntries(credentialFields[values.provider_type].map(
        (field) => [field.name, values.credentials[field.name]],
      ))
      startProviderWrite({
        kind: 'create',
        input: {
          ...(targetScopeID ? { target_scope_id: targetScopeID } : {}),
          name: values.name.trim(), remark: (values.remark ?? '').trim(), provider_type: values.provider_type, credentials,
        },
      })
      return
    }
    const item = providerEditor.item
    startProviderWrite({
      kind: 'update',
      id: item.id,
      providerType: item.provider_type,
      input: {
        expected_version: item.version,
        name: values.name.trim(),
        remark: (values.remark ?? '').trim(),
        status: isCreatableProviderType(item.provider_type) ? values.status : 'disabled',
        ...(isCreatableProviderType(item.provider_type) && values.replace_credentials ? {
          credentials: Object.fromEntries(credentialFields[item.provider_type].map(
            (field) => [field.name, values.credentials[field.name]],
          )),
        } : {}),
      },
    })
  }

  const closeProviderAndRefresh = () => {
    clearProviderWriteCredentials(providerAttemptRef.current)
    providerAttemptRef.current = null
    setProviderAttempt(null)
    setProviderWriteError(null)
    setProviderEditor(null)
    if (currentSessionAccess('dns.read')) void providersQuery.refetch()
  }

  const saveCertificateDefaults = () => {
    if (!currentSessionAccess('certificates.manage') || !targetUser || !defaultsQuery.data || defaultsLocked) return
    const input: UpdateCertificateDefaultsInput = {
      ...(targetScopeID ? { target_scope_id: targetScopeID } : {}),
      target_user_id: targetUser.id,
      certificate_type: defaultType,
      ...(defaultType === 'acme' && defaultProviderID ? { dns_provider_id: defaultProviderID } : {}),
      ...(defaultType === 'acme' && defaultIssuer ? { issuer: defaultIssuer } : {}),
      expected_revision: defaultsQuery.data.revision,
    }
    const next = { input, key: `certificate-defaults-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}` }
    defaultsAttemptRef.current = next
    setDefaultWriteError(null)
    defaultsMutation.mutate()
  }

  const deleteSelectedProviders = async () => {
    const token = currentSessionAccess('dns.manage')
    if (!token) return
    const selected = providerItems.filter((item) => selectedProviderIDs.includes(item.id))
    try {
      for (const item of selected) {
        await dnsApi.remove(token, item.id, item.version, providerWriteKey('delete'))
      }
      setSelectedProviderIDs([])
      await providersQuery.refetch()
    } catch (error) {
      if (currentSessionMatches()) setProviderWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
    }
  }

  const submit = (values: CertificateForm) => {
    if (!currentSessionAccess('certificates.manage')) return
    if (queryOwner[0] === 'platform' && !orderScopeID) {
      setWriteError(new ApiError('owner required', 422, 'certificate_target_required'))
      return
    }
    const domains = normalizedDomains(values.domains_text)
    if (!domains) {
      form.setFields([{ name: 'domains_text', errors: [t('validation.domainsInvalid')] }])
      return
    }
    if (domains.some((domain) => domain.startsWith('*.')) && values.challenge_type !== 'dns-01') {
      form.setFields([{ name: 'challenge_type', errors: [t('validation.wildcardRequiresDns')] }])
      return
    }
    if (values.challenge_type === 'dns-01' && !values.dns_provider_id) {
      form.setFields([{ name: 'dns_provider_id', errors: [t('validation.dnsProviderRequired')] }])
      return
    }
    const input: CreateCertificateOrderInput = {
      domains,
      challenge_type: values.challenge_type,
      auto_renew: values.auto_renew,
      ...(values.name?.trim() ? { name: values.name.trim() } : {}),
      ...(values.remark?.trim() ? { remark: values.remark.trim() } : {}),
      ...(explicitIssuer ? { issuer: explicitIssuer } : {}),
      ...(orderScopeID ? { target_scope_id: orderScopeID } : {}),
      ...(values.challenge_type === 'dns-01' ? { dns_provider_id: values.dns_provider_id } : {}),
    }
    const next = orderAttemptFor(input)
    orderAttemptRef.current = next
    setAttempt(next)
    setWriteError(null)
    setOrderFieldMarked(false)
    mutation.mutate()
  }

  // ---- CERT-04 统一“添加证书”：单个（自己上传 / CA）与批量申请 ----
  const [requestOnly, setRequestOnly] = useState(() => initialDomainsRef.current.trim().length > 0)
  const batchRowsRef = useRef<BatchRow[]>([])
  const updateBatchRows = (update: (rows: BatchRow[]) => BatchRow[]) => {
    batchRowsRef.current = update(batchRowsRef.current)
    setBatchRows(batchRowsRef.current)
  }
  // “添加证书”固定列出 ZeroSSL 与 Let's Encrypt；ZeroSSL 未配置 EAB 时置灰并说明。
  const zeroSSLUnconfigured = issuersQuery.isSuccess && !offeredIssuers.includes('zerossl')
  const issuerCards: CertificateIssuer[] = offeredIssuers.length > 0 ? offeredIssuers : ['lets_encrypt']
  const shownIssuerCards: CertificateIssuer[] = !requestOnly && zeroSSLUnconfigured ? ['zerossl', ...issuerCards] : issuerCards
  // 签发机构列表未就绪时不带 issuer，由后端按默认设置/平台默认决定
  const explicitIssuer = issuersQuery.isSuccess && offeredIssuers.includes(selectedIssuer) ? selectedIssuer : undefined

  const resetAddAttempts = () => {
    uploadAttemptRef.current = null; setAssetAttempt(null); setAssetWriteError(null)
    orderAttemptRef.current = null; setAttempt(null); setWriteError(null); setAccepted(false)
  }
  // 平台“默认设置/DNS API”已选的用户即当前上下文用户，手动申请时默认带入（仍可改选）。
  const contextOwner = contextUser ?? null
  const openAdd = () => {
    if (!currentSessionAccess('certificates.manage')) return
    resetAddAttempts()
    setUploadOwner(contextOwner); setOrderOwner(contextOwner); setFromSite(false); setReapplyScopeID(undefined); setRequestOnly(false)
    batchRowsRef.current = []; setBatchRows([]); setBatchOpen(false)
    issuerTouchedRef.current = false
    autoTypeRef.current = true
    const uploadedDefault = isTenant && defaultsQuery.data?.certificate_type === 'uploaded'
    if (uploadedDefault) autoTypeRef.current = false
    setUploadOpen(uploadedDefault)
    setEditorOpen(!uploadedDefault)
  }
  const openRequest = () => {
    if (!currentSessionAccess('certificates.manage')) return
    resetAddAttempts()
    setOrderOwner(contextOwner); setFromSite(false); setReapplyScopeID(undefined); setRequestOnly(true)
    issuerTouchedRef.current = false
    autoTypeRef.current = false
    setUploadOpen(false); setBatchOpen(false); setEditorOpen(true)
  }
  const chooseUpload = () => {
    autoTypeRef.current = false
    if (uploadOpen) return
    carryRef.current = { name: form.getFieldValue('name'), remark: form.getFieldValue('remark') }
    if (queryOwner[0] === 'platform') setUploadOwner(orderOwner)
    resetAddAttempts()
    setEditorOpen(false); setUploadOpen(true)
  }
  const chooseIssuer = (issuer: CertificateIssuer) => {
    autoTypeRef.current = false
    issuerTouchedRef.current = true
    setSelectedIssuer(issuer)
    if (!uploadOpen) return
    carryRef.current = { name: uploadForm.getFieldValue('name'), remark: uploadForm.getFieldValue('remark') }
    if (queryOwner[0] === 'platform') setOrderOwner(uploadOwner)
    resetAddAttempts()
    setUploadOpen(false); setEditorOpen(true)
  }
  const chooseAddTab = (tab: 'single' | 'batch') => {
    if ((tab === 'batch') === batchOpen) return
    resetAddAttempts()
    batchRowsRef.current = []; setBatchRows([])
    setUploadOpen(false); setEditorOpen(tab === 'single'); setBatchOpen(tab === 'batch')
  }
  // 默认设置晚于弹窗到达时，用户还没点选类型就按默认类型切换一次
  useEffect(() => {
    if (!autoTypeRef.current || !addOpen || batchOpen || requestOnly || !addDefaults) return
    autoTypeRef.current = false
    if (addDefaults.certificate_type === 'uploaded' && editorOpen && !attempt) chooseUpload()
  })
  // 可用 DNS 服务商只有一个时自动选中（两个及以上才让用户选）。
  // DNS-SEC-20261027-01：平台托管的 DNS 副本不能用于用户本人的 DNS 验证（服务端同样拒绝）；平台管理员代申请照常可选。
  const usableProviders = useMemo(() => (providersQuery.data?.items ?? []).filter((item) => item.status !== 'disabled' &&
    !(isTenant && item.managed_by === 'platform')), [providersQuery.data?.items, isTenant])
  useEffect(() => {
    if (usableProviders.length !== 1) return
    const only = usableProviders[0]!.id
    if (editorOpen && challenge === 'dns-01' && !form.getFieldValue('dns_provider_id')) form.setFieldValue('dns_provider_id', only)
    if (batchOpen && !batchForm.getFieldValue('dns_provider_id')) batchForm.setFieldValue('dns_provider_id', only)
  }, [batchForm, batchOpen, challenge, editorOpen, form, usableProviders])
  // 批量申请也带入默认 DNS 账号（CERT-03）
  const batchProviderAppliedRef = useRef<string | null>(null)
  useEffect(() => {
    if (!batchOpen) { batchProviderAppliedRef.current = null; return }
    const applied = isTenant ? 'self' : addTargetKey
    if (!applied || batchProviderAppliedRef.current === applied || !addDefaults || !providersQuery.data) return
    if (!isTenant && providersQuery.data.items.some((item) => item.scope_id !== addTarget?.scopeID)) return
    batchProviderAppliedRef.current = applied
    const providerID = addDefaults.certificate_type === 'acme' ? addDefaults.dns_provider_id : undefined
    if (providerID && !batchForm.getFieldValue('dns_provider_id') &&
      providersQuery.data.items.some((item) => item.id === providerID && item.status !== 'disabled' &&
        (!isTenant || item.managed_by !== 'platform'))) {
      batchForm.setFieldValue('dns_provider_id', providerID)
    }
  }, [addDefaults, addTarget?.scopeID, addTargetKey, batchForm, batchOpen, isTenant, providersQuery.data])

  const batchStarted = batchRows.length > 0
  const batchRetryable = batchRows.some((row) => row.status === 'failed' || row.status === 'unknown')
  const runBatch = async () => {
    if (batchRunning) return
    setBatchRunning(true)
    try {
      for (const row of batchRowsRef.current) {
        if (row.status === 'accepted' || row.status === 'running') continue
        const token = currentSessionAccess('certificates.manage')
        if (!token || (row.input.dns_provider_id && !currentSessionAccess('dns.read'))) {
          updateBatchRows((rows) => rows.map((item) => item.line === row.line ? { ...item, status: 'failed', error: certificatePermissionDenied() } : item))
          continue
        }
        // 已明确失败的行没有建单，可换新幂等键；结果未知的行必须用原键重试
        const key = row.status === 'failed' ? writeKey() : row.key
        updateBatchRows((rows) => rows.map((item) => item.line === row.line ? { ...item, key, status: 'running', error: undefined } : item))
        try {
          const value = await certificatesApi.create(token, row.input, key)
          if (!currentSessionMatches()) return
          assertOrderOwner(queryOwner, value, row.input.target_scope_id)
          if (!orderReceiptMatches(value, row.input)) throw invalidCertificateResponse()
          updateBatchRows((rows) => rows.map((item) => item.line === row.line ? { ...item, status: 'accepted' } : item))
        } catch (error) {
          if (!currentSessionMatches()) return
          const apiError = error instanceof ApiError ? error : new ApiError('request failed')
          updateBatchRows((rows) => rows.map((item) => item.line === row.line
            ? { ...item, status: outcomeUnknown(error) ? 'unknown' : 'failed', error: apiError } : item))
        }
      }
    } finally {
      if (currentSessionMatches()) {
        setBatchRunning(false)
        void queryClient.invalidateQueries({ queryKey: orderPrefix })
      }
    }
  }
  const submitBatch = (values: BatchForm) => {
    if (!currentSessionAccess('certificates.manage')) return
    if (queryOwner[0] === 'platform' && !orderScopeID) {
      setWriteError(new ApiError('owner required', 422, 'certificate_target_required'))
      return
    }
    const lines = values.lines.split(/\r?\n/).map((line, index) => ({ line: index + 1, text: line.trim() })).filter((item) => item.text)
    const invalid: number[] = []
    const wildcardWithoutDNS: number[] = []
    const rows: BatchRow[] = []
    for (const item of lines) {
      const domains = normalizedDomains(item.text)
      if (!domains) { invalid.push(item.line); continue }
      if (!values.dns_provider_id && domains.some((domain) => domain.startsWith('*.'))) { wildcardWithoutDNS.push(item.line); continue }
      rows.push({
        line: item.line, domains, key: writeKey(), status: 'pending',
        input: {
          domains,
          challenge_type: values.dns_provider_id ? 'dns-01' : 'http-01',
          auto_renew: true,
          ...(explicitIssuer ? { issuer: explicitIssuer } : {}),
          ...(orderScopeID ? { target_scope_id: orderScopeID } : {}),
          ...(values.dns_provider_id ? { dns_provider_id: values.dns_provider_id } : {}),
        },
      })
    }
    const errors = [
      ...(lines.length > batchLineLimit ? [t('batch.tooMany', { count: batchLineLimit })] : []),
      ...(invalid.length ? [t('batch.invalidLines', { lines: invalid.join('、') })] : []),
      ...(wildcardWithoutDNS.length ? [t('batch.wildcardLines', { lines: wildcardWithoutDNS.join('、') })] : []),
    ]
    if (errors.length) {
      batchForm.setFields([{ name: 'lines', errors }])
      return
    }
    setWriteError(null)
    batchRowsRef.current = rows
    setBatchRows(rows)
    void runBatch()
  }
  // ZeroSSL EAB 在“默认设置”页由平台管理员填写（system_configuration.manage）。
  const canManageEAB = queryOwner[0] === 'platform' && Boolean(sessionPrincipal && (sessionPrincipal.permissions.includes('system_configuration.manage') || sessionPrincipal.permissions.includes('platform.admin')))
  const openEABSettings = () => { closeAdd(); setSectionTab('default'); onSectionChange?.('default') }
  const closeAdd = () => {
    if (batchRunning || writesLocked || assetWritesLocked) return
    resetAddAttempts()
    const created = batchRowsRef.current.some((row) => row.status !== 'pending')
    batchRowsRef.current = []; setBatchRows([])
    setUploadOpen(false); setEditorOpen(false); setBatchOpen(false)
    uploadForm.resetFields()
    if (created && currentSessionAccess('certificates.read')) void assetsQuery.refetch()
  }

  const orders = useMemo(() => query.data?.items ?? [], [query.data?.items])
  const assetRows = useMemo<CertificateAssetRow[]>(() => assetPageItems.map((asset, index) => {
    const detail = assetDetailQueries[index]?.data
    const version = latestAssetVersion(detail)
    return {
      asset,
      detail,
      version,
      order: orders.find((order) => order.issued_asset_id === asset.id),
      inFlight: Boolean(version) && orders.some((order) => orderInFlightFor(order, asset, version!)),
      filter: assetStatusFilter(version),
    }
  }), [assetDetailQueries, assetPageItems, orders])
  // 高级筛选已由服务端执行；这里只是当前页的行。
  const filteredAssetRows = assetRows
  const hasActiveAssetFilter = search.trim() !== '' || assetFilter !== 'all' ||
    Object.values(appliedFilters).some((value) => Boolean(value))
  const assetCounts = assetsQuery.data?.counts
  const assetStats = {
    all: assetCounts?.all ?? 0,
    normal: assetCounts?.normal ?? 0,
    expiring: assetCounts?.expiring ?? 0,
    expired: assetCounts?.expired ?? 0,
    autoRenew: assetCounts?.auto_renew ?? 0,
    manualRenew: assetCounts?.manual_renew ?? 0,
  }

  // 手动上传的证书没有申请参数；后端下单只会另签一张新证书（不续这张），所以不提供重新申请。
  // 已有进行中的同域名申请时也不重复提交。
  const reapplyBlock = (row: CertificateAssetRow): string | null => {
    if (row.asset.source === 'uploaded') return assetT('reapply.uploadedUnsupported')
    if (row.inFlight) return assetT('reapply.inFlight')
    return null
  }
  const openReapply = (row: CertificateAssetRow) => {
    if (!canManage || !row.version || reapplyBlock(row) || !currentSessionAccess('certificates.manage')) return
    const source = orders.find((order) => order.id === row.version?.acme_order_id) ?? row.order
    if (source) {
      // 有原订单：不弹表单，确认后按原参数直接下单。
      const input = reapplyOrderInput(source, queryOwner[0] === 'platform' ? row.asset.tenant_scope_id : undefined)
      orderAttemptRef.current = null
      setAttempt(null)
      setAccepted(false)
      setWriteError(null)
      setReapplyTarget({ name: row.asset.name, input })
      return
    }
    // 上传的证书没有申请参数：仍打开申请表单，域名预填。
    setReapplyScopeID(row.asset.tenant_scope_id)
    setOrderOwner(null)
    setFromSite(false)
    autoTypeRef.current = false
    issuerTouchedRef.current = false
    setRequestOnly(true)
    setUploadOpen(false)
    setBatchOpen(false)
    initialDomainsRef.current = row.version.sans.join('\n')
    initialChallengeRef.current = 'dns-01'
    orderAttemptRef.current = null
    setAttempt(null)
    setAccepted(false)
    setWriteError(null)
    setEditorOpen(true)
  }

  const selectedRow = selectedAssetIDs.length === 1
    ? assetRows.find((row) => row.asset.id === selectedAssetIDs[0])
    : undefined
  const selectedAssets = assetRows.filter((row) => selectedAssetIDs.includes(row.asset.id))
  // 批量动作只作用于适用的证书：启用/禁用按当前状态，续签开关只对自动签发，下载跳过已吊销。
  const runBulk = (action: BulkAction) => {
    const applicable = selectedAssets.filter((row) => {
      if (action === 'enable') return Boolean(row.asset.disabled)
      if (action === 'disable') return !row.asset.disabled
      if (action === 'enableAutoRenew') return row.asset.source === 'acme' && !row.asset.auto_renew
      if (action === 'disableAutoRenew') return row.asset.source === 'acme' && Boolean(row.asset.auto_renew)
      if (action === 'download') return Boolean(row.version) && row.version?.status !== 'revoked'
      return true
    }).map((row) => row.asset)
    if (applicable.length === 0) { message.info(assetT('certOps.bulkNone')); return }
    if (action === 'delete') {
      modal.confirm({
        title: assetT('delete.title'), content: assetT('certOps.bulkDeleteConfirm', { count: applicable.length }),
        okText: assetT('assetActions.delete'), okButtonProps: { danger: true },
        onOk: () => bulkMutation.mutate({ action, assets: applicable }),
      })
      return
    }
    bulkMutation.mutate({ action, assets: applicable })
  }

  const exportAssets = () => {
    const selected = selectedAssetIDs.length > 0
      ? filteredAssetRows.filter((row) => selectedAssetIDs.includes(row.asset.id))
      : filteredAssetRows
    if (selected.length === 0) return
    const header = [
      assetT('assetColumns.id'), ...(isTenant ? [] : [assetT('assetColumns.user')]), assetT('assetColumns.name'),
      ...(queryOwner[0] === 'platform' ? [assetT('assetColumns.tenant')] : []),
      assetT('assetColumns.domains'), assetT('assetColumns.type'), assetT('assetColumns.createdAt'),
      assetT('assetColumns.expiresAt'), assetT('assetColumns.autoRenew'), assetT('assetColumns.status'),
    ]
    const rows = selected.map((row) => [
      row.asset.display_id,
      ...(isTenant ? [] : [row.asset.owner?.username ?? assetT('assetValues.legacyOwner')]),
      row.asset.name,
      ...(queryOwner[0] === 'platform' ? [assetT('assetValues.tenant', { name: row.asset.tenant.name, id: row.asset.tenant.display_id })] : []),
      row.version?.sans.join(' ') ?? '',
      assetT(`assetSources.${row.asset.source}`),
      formatDateTime(row.asset.created_at, i18n.resolvedLanguage) || row.asset.created_at,
      row.version ? formatDateTime(row.version.not_after, i18n.resolvedLanguage) || row.version.not_after : '',
      assetT(row.asset.auto_renew ? 'values.enabled' : 'values.disabled'),
      row.version ? assetT(`assetStates.${row.version.status}`) : assetT('assetStates.unknown'),
    ])
    const csv = [header, ...rows].map((row) => row.map((value) => csvValue(String(value))).join(',')).join('\r\n')
    const url = URL.createObjectURL(new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = assetT('export.fileName')
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const openOrders = (row?: CertificateAssetRow) => {
    setOrderAsset(row ? { id: row.asset.id, sans: row.version?.sans ?? [] } : null)
    setActiveTab('orders'); setPage(1); setSearch('')
  }
  const closeOrders = () => { setOrderAsset(null); setActiveTab('assets'); setPage(1); setSearch('') }
  const assetColumns: TableColumnsType<CertificateAssetRow> = [
    {
      title: assetT('assetColumns.id'), key: 'id', width: certificateColumnWidths.assets.id, ellipsis: true,
      render: (_, row) => <span>{row.asset.display_id}</span>,
    },
    ...(isTenant ? [] : [{
      title: assetT('assetColumns.user'), key: 'user', width: certificateColumnWidths.assets.user,
      render: (_, row) => (
        <span className="certificate-user-cell" title={row.asset.owner?.username ?? assetT('assetValues.legacyOwnerHint')}>
          <span>{row.asset.owner?.username ?? assetT('assetValues.legacyOwner')}</span>
          {row.asset.owner ? <small>{assetT('assetValues.userID', { id: row.asset.owner.display_id })}</small> : null}
          {queryOwner[0] === 'platform' ? <small>{assetT('assetValues.tenant', { name: row.asset.tenant.name, id: row.asset.tenant.display_id })}</small> : null}
        </span>
      ),
    } satisfies TableColumnsType<CertificateAssetRow>[number]]),
    {
      title: assetT('assetColumns.name'), key: 'certificate', width: certificateColumnWidths.assets.certificate,
      render: (_, row) => (
        <span className="certificate-info-cell">
          <strong title={row.asset.name}>{row.asset.name}</strong>
          <small title={row.version?.sans.join(', ') ?? undefined}>
            <span>{assetT('assetColumns.domains')}</span>
            {row.version?.sans.join(', ') ?? assetT('assetValues.loading')}
          </small>
        </span>
      ),
    },
    {
      title: assetT('assetColumns.type'), key: 'type', width: certificateColumnWidths.assets.type,
      render: (_, row) => assetT(`assetSources.${row.asset.source}`),
    },
    {
      title: assetT('assetColumns.createdAt'), key: 'createdAt', width: certificateColumnWidths.assets.createdAt,
      render: (_, row) => stackedDateTime(formatDateTime(row.asset.created_at, i18n.resolvedLanguage) || row.asset.created_at),
    },
    {
      title: assetT('assetColumns.expiresAt'), key: 'expiresAt', width: certificateColumnWidths.assets.expiresAt,
      render: (_, row) => row.version
        ? stackedDateTime(formatDateTime(row.version.not_after, i18n.resolvedLanguage) || row.version.not_after)
        : assetT('assetValues.loading'),
    },
    {
      title: assetT('assetColumns.autoRenew'), key: 'autoRenew', width: certificateColumnWidths.assets.autoRenew,
      // 可直接点击的开关；手动上传或无修改权限时禁用并悬浮说明。
      render: (_, row) => {
        const pending = autoRenewPending[row.asset.id]
        const blocked = row.asset.source === 'uploaded' ? assetT('autoRenew.uploaded')
          : !canManage ? assetT('autoRenew.noPermission') : null
        const toggle = (
          <Switch
            size="small"
            aria-label={assetT('autoRenew.label')}
            checked={pending ?? Boolean(row.asset.auto_renew)}
            loading={pending !== undefined}
            disabled={Boolean(blocked)}
            onChange={(enabled) => autoRenewMutation.mutate({ asset: row.asset, enabled })}
          />
        )
        return blocked ? <Tooltip title={blocked}><span className="certificate-blocked-action">{toggle}</span></Tooltip> : toggle
      },
    },
    {
      title: assetT('assetColumns.status'), key: 'status', width: certificateColumnWidths.assets.status,
      // 有进行中的重新申请/续签时，在状态旁标“申请中”。
      render: (_, row) => <>
        {/* 禁用优先于版本状态，状态列只放一个标签。 */}
        {row.asset.disabled ? <Tooltip title={assetT('certOps.disabledHint')}><Tag>{assetT('assetStates.disabled')}</Tag></Tooltip> : row.version ? (
          <Tag color={row.filter === 'expired' ? 'error' : row.filter === 'expiring' ? 'warning' : row.filter === 'normal' ? 'success' : 'processing'}>
            {assetT(`assetStates.${row.version.status}`)}
          </Tag>
        ) : <Tag>{assetT('assetStates.loading')}</Tag>}
        {row.inFlight ? (
          <Button type="link" size="small" className="certificate-applying-link" title={assetT('assetActions.orders')} onClick={() => openOrders(row)}>
            <Tag color="processing">{assetT('assetStates.applying')}</Tag>
          </Button>
        ) : null}
      </>,
    },
    {
      title: assetT('assetColumns.actions'), key: 'actions', width: certificateColumnWidths.assets.actions, fixed: 'right',
      render: (_, row) => (
        <span className="certificate-row-actions">
          <Button type="link" size="small" aria-label={assetT('assetActions.detail')} loading={detailLoading} onClick={() => void loadDetail(row.asset)}>{assetT('assetActions.manage')}</Button>
          {canManage ? (() => {
            const blocked = reapplyBlock(row)
            const button = <Button type="link" size="small" disabled={!row.version || blocked !== null} onClick={() => openReapply(row)}>{assetT('assetActions.reapply')}</Button>
            return blocked ? <Tooltip title={blocked}><span className="certificate-blocked-action">{button}</span></Tooltip> : button
          })() : null}
          {/* 行内只留 管理 · 重新申请 · 更多▼，其余单张操作都在“更多”里，按状态显示可用项。
              更多里不重复“重新申请”；“吊销”下线（只改本地状态、与禁用重叠）。 */}
          <Dropdown
            trigger={['click']}
            menu={{
              items: [
                ...(canManage ? [{ key: 'download', label: assetT('assetActions.download'), disabled: !row.version || row.version.status === 'revoked' || downloadMutation.isPending }] : []),
                ...(canManage ? [row.asset.disabled
                  ? { key: 'enable', label: assetT('assetActions.enable'), disabled: disabledMutation.isPending }
                  : { key: 'disable', label: assetT('assetActions.disable'), disabled: disabledMutation.isPending }] : []),
                { key: 'orders', label: assetT('assetActions.orders') },
                ...(canManage ? [
                  { key: 'bind', label: assetT('assetActions.bind'), disabled: Boolean(row.asset.disabled) || !row.version || !['active', 'default'].includes(row.version.status) },
                  { type: 'divider' as const },
                  { key: 'delete', danger: true, label: assetT('assetActions.delete') },
                ] : []),
              ],
              onClick: ({ key }) => {
                if (key === 'download') downloadMutation.mutate(row.asset)
                if (key === 'enable' || key === 'disable') disabledMutation.mutate({ asset: row.asset, disabled: key === 'disable' })
                if (key === 'orders') openOrders(row)
                if (key === 'bind') void loadDetail(row.asset)
                if (key === 'delete') {
                  if (!currentSessionAccess('certificates.manage')) return
                  commandAttemptRef.current = null
                  setCommandAttempt(null)
                  setCommandError(null)
                  setDeleteTarget(row.asset)
                }
              },
            }}
          >
            <Button type="link" size="small" aria-label={assetT('assetActions.rowMoreNamed', { name: row.asset.name })}>
              {assetT('assetActions.rowMore')} <ChevronDown size={13} aria-hidden />
            </Button>
          </Dropdown>
        </span>
      ),
    },
  ]

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    // One certificate's requests: those that issued it, or ones for exactly its domains (renewals in flight).
    const scoped = orderAsset ? orders.filter((item) => item.issued_asset_id === orderAsset.id ||
      sameDomainSet(item.domains, orderAsset.sans)) : orders
    return term ? scoped.filter((item) => item.domains.some((domain) => domain.toLowerCase().includes(term))) : scoped
  }, [orderAsset, orders, search])
  const pageItems = useMemo(() => filtered.slice((page - 1) * limit, page * limit), [filtered, limit, page])
  const columns: TableColumnsType<CertificateOrder> = [
    {
      title: t('columns.domains'), dataIndex: 'domains', width: certificateColumnWidths.orders.domains, ellipsis: true,
      render: (domains: string[]) => <span title={domains.join(', ')}>{domains.join(', ')}</span>,
    },
    {
      title: t('columns.challenge'), dataIndex: 'challenge_type', width: certificateColumnWidths.orders.challenge,
      // “HTTP-01（文件验证）”放不下一行时换行，不截断。
      render: (value: CertificateChallengeType) => <span className="certificate-wrap-cell">{t(`challenges.${value.replace('-', '_')}`)}</span>,
    },
    {
      title: t('columns.status'), dataIndex: 'status', width: certificateColumnWidths.orders.status,
      render: (value: CertificateOrderStatus, order: CertificateOrder) => <>
        <Tag color={statusColor(value)}>{t(`states.${value}`)}</Tag>
        {orderStuck(order, Date.now()) ? <Tag color="warning" title={assetT('stuck.hint')}>{assetT('stuck.label')}</Tag> : null}
      </>,
    },
    {
      title: t('columns.autoRenew'), dataIndex: 'auto_renew', width: certificateColumnWidths.orders.autoRenew,
      render: (value: boolean) => t(value ? 'values.enabled' : 'values.disabled'),
    },
    {
      title: t('columns.notAfter'), dataIndex: 'not_after', width: certificateColumnWidths.orders.notAfter,
      render: (value?: string) => value ? stackedDateTime(formatDateTime(value, i18n.resolvedLanguage) || t('values.pending')) : t('values.pending'),
    },
    {
      title: t('columns.failure'), dataIndex: 'failure_code', width: certificateColumnWidths.orders.failure,
      // 失败原因最多两行，超出部分省略，悬浮显示全文；CA 原因跟在分类文案后。
      render: (_: unknown, order: CertificateOrder) => <CertificateFailureReason order={order} fallback={t('values.pending')} />,
    },
    {
      title: t('columns.createdAt'), dataIndex: 'created_at', width: certificateColumnWidths.orders.createdAt,
      render: (value: string) => stackedDateTime(formatDateTime(value, i18n.resolvedLanguage) || value),
    },
  ]
	  const versionColumns: TableColumnsType<CertificateAssetVersion> = [
	    { title: assetT('versionColumns.version'), dataIndex: 'version', width: 80 },
	    {
	      title: assetT('versionColumns.status'), dataIndex: 'status', width: 130,
	      render: (value: CertificateAssetVersion['status']) => assetT(`assetStates.${value}`),
	    },
	    {
	      title: assetT('versionColumns.domains'), dataIndex: 'sans', width: 220, ellipsis: true,
      render: (value: string[]) => <span title={value.join(', ')}>{value.join(', ')}</span>,
    },
		{
		  title: assetT('versionColumns.notAfter'), dataIndex: 'not_after', width: 180,
		  render: (value: string) => formatDateTime(value, i18n.resolvedLanguage) || value,
		},
		{
		  title: assetT('versionColumns.acmeOrder'), dataIndex: 'acme_order_id', width: 180, ellipsis: true,
		  render: (value?: string) => value ?? assetT('values.none'),
		},
		{
		  title: assetT('versionColumns.renewal'), dataIndex: 'renewal_due', width: 120,
		  render: (value: boolean, version) => value ? <span title={version.renewal_due_at ?? undefined}>{assetT('renewal.due')}</span> : assetT('renewal.notDue'),
		},
		{
		  title: assetT('versionColumns.actions'), key: 'actions', width: 120,
		  render: (_, version) => canManage && !['active', 'revoked', 'expired'].includes(version.status)
			? <Button type="link" size="small" disabled={commandLocked} onClick={() => activateVersion(version)}>{assetT('assetActions.activate')}</Button>
			: null,
		},
	  ]
	  const bindingColumns: TableColumnsType<CertificateAssetBinding> = [
		{ title: assetT('bindingColumns.site'), dataIndex: 'site_id', width: 280, ellipsis: true },
		{ title: assetT('bindingColumns.revision'), dataIndex: 'revision', width: 100 },
		{ title: assetT('bindingColumns.default'), dataIndex: 'default', width: 100, render: (value: boolean) => assetT(value ? 'values.enabled' : 'values.disabled') },
		{
		  title: assetT('bindingColumns.actions'), key: 'actions', width: 100,
		  render: (_, binding) => canManage
			? <Button type="link" danger size="small" disabled={commandLocked} onClick={() => unbind(binding)}>{assetT('assetActions.unbind')}</Button>
			: null,
		},
	  ]

  const providerLabels: Record<string, string> = {
    aliyun: dnsT('providers.aliyun'),
    cloudflare: dnsT('providers.cloudflare'),
    huawei: dnsT('providers.huawei'),
    dnspod_cn: dnsT('providers.dnspod_cn'),
    dns_com: dnsT('providers.dns_com'),
    dns_la: dnsT('providers.dns_la'),
    namecom: dnsT('providers.namecom'),
    dnsdun: dnsT('providers.dnsdun'),
  }
  const providerItems = providersQuery.data?.items ?? []
  const providerPageItems = useMemo(
    () => providerItems.slice((providerPage - 1) * providerLimit, providerPage * providerLimit),
    [providerItems, providerLimit, providerPage],
  )
  const certificateProviderColumns: TableColumnsType<DNSProvider> = [
    // CERT-07b：DNS 服务商接口不返回归属用户，不再显示整列占位的"用户"列。
    { title: 'ID', dataIndex: 'id', width: 190, ellipsis: true },
    {
      title: t('dnsApi.columns.name'), dataIndex: 'name', width: 220, ellipsis: true,
      render: (value: string, item) => item.managed_by === 'platform' ? (
        <Space size={6}>
          <span>{value}</span>
          <Tooltip title={dnsT('platformManaged.hint')}><Tag>{dnsT('platformManaged.tag')}</Tag></Tooltip>
        </Space>
      ) : value,
    },
    {
      title: t('dnsApi.columns.type'), dataIndex: 'provider_type', width: 180,
      render: (value: string) => providerLabels[value] ?? dnsT('providers.unknown', { type: value }),
    },
    {
      title: t('dnsApi.columns.remark'), key: 'remark', width: 180, ellipsis: true,
      render: (_, item) => {
        const remark = item.remark?.trim()
        if (item.status === 'disabled') return remark ? `${remark}（${dnsT('states.disabled')}）` : dnsT('states.disabled')
        return remark || '—'
      },
    },
    {
      title: t('dnsApi.columns.actions'), key: 'actions', width: 150, fixed: 'right',
      render: (_, item) => canManageDNS && item.managed_by !== 'platform' ? (
        <Space size={2}>
          {isCreatableProviderType(item.provider_type) ? (
            <Tooltip title={dnsT('actions.verify')}>
              <Button
                type="text" size="small" aria-label={dnsT('actions.verifyNamed', { name: item.name })}
                icon={<CircleCheck size={15} />} disabled={providerWritesLocked || item.status === 'disabled'}
                onClick={() => startProviderWrite({ kind: 'verify', id: item.id, providerType: item.provider_type, version: item.version })}
              />
            </Tooltip>
          ) : null}
          <Tooltip title={dnsT('actions.edit')}>
            <Button
              type="text" size="small" aria-label={dnsT('actions.editNamed', { name: item.name })}
              icon={<Pencil size={15} />} disabled={providerWritesLocked}
              onClick={() => { setProviderWriteError(null); setProviderEditor({ mode: 'edit', item }) }}
            />
          </Tooltip>
          <Popconfirm
            title={dnsT('confirm.delete')} okText={dnsT('actions.delete')} cancelText={dnsT('actions.cancel')}
            okButtonProps={{ danger: true }}
            onConfirm={() => startProviderWrite({ kind: 'delete', id: item.id, version: item.version })}
          >
            <Tooltip title={dnsT('actions.delete')}>
              <Button danger type="text" size="small" aria-label={dnsT('actions.deleteNamed', { name: item.name })} icon={<Trash2 size={15} />} disabled={providerWritesLocked} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ) : null,
    },
  ]

  const activeError = sectionTab === 'dnsApi'
    ? providersQuery.error
    : sectionTab === 'list'
      ? (activeTab === 'assets' ? assetsQuery.error : query.error)
      : null
  // 搜索框与高级条件边输入边生效（文本 400ms 防抖，下拉选完即查）。
  useLiveApply({ search: searchDraft, filters: filterDraft }, { search, filters: appliedFilters }, (next) => applyLiveRef.current(next.filters))
  const idSearchToken = currentSessionAccess('certificates.read') ?? ''
  const certificateIDSearch = useMemo(() => certificateSearch(idSearchToken), [idSearchToken])
  const ownerSearch = useMemo(() => userSearch(idSearchToken, 'display_id'), [idSearchToken])
  if (activeError instanceof ApiError && activeError.status === 403) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permission_denied')} />
  }
  const queryError = activeError instanceof ApiError ? activeError : null
  const updateFilterDraft = (patch: Partial<CertificateFilterDraft>) => {
    setFilterDraft((current) => ({ ...current, ...patch }))
  }
  const resetAdvancedFilters = () => {
    setFilterDraft(emptyFilterDraft)
    setAppliedFilters(emptyFilterDraft)
    setAssetFilter('all')
    setPage(1)
  }
  // 高级条件进共享 AdvancedFilters；应用/去掉单项/清空都即刻按服务端筛选重查。
  const applyAdvancedFilters = (next: CertificateFilterDraft) => {
    setFilterDraft(next)
    setAppliedFilters({ ...next })
    setSearch(searchDraft)
    setPage(1)
  }
  applyLiveRef.current = applyAdvancedFilters
  const typeOptions = [{ value: 'uploaded', label: assetT('advancedFilters.typeUploaded') }, { value: 'acme', label: assetT('advancedFilters.typeAcme') }]
  const dnsApiOptions = providerItems.map((item) => ({ value: item.id, label: item.name }))
  const expiresOptions = [{ value: '30', label: assetT('advancedFilters.expiry30') }, { value: '90', label: assetT('advancedFilters.expiry90') }, { value: 'expired', label: assetT('advancedFilters.expiryExpired') }]
  const enabledOptions = [{ value: 'on', label: assetT('advancedFilters.enabledOn') }, { value: 'off', label: assetT('advancedFilters.enabledOff') }]
  const issueOptions = [{ value: 'issued', label: assetT('advancedFilters.issued') }, { value: 'failed', label: assetT('advancedFilters.failed') }]
  const syncOptions = [{ value: 'complete', label: assetT('advancedFilters.syncComplete') }, { value: 'pending', label: assetT('advancedFilters.syncPending') }, { value: 'failed', label: assetT('advancedFilters.syncFailed') }]
  const textFilter = (key: 'domain' | 'multiDomain' | 'user' | 'certificateID' | 'name' | 'remark'): AdvancedFilterItem => ({
    key,
    label: assetT(`advancedFilters.${key}`),
    applied: appliedFilters[key],
    field: key === 'multiDomain'
      ? <Input.TextArea aria-label={assetT('advancedFilters.multiDomain')} value={filterDraft.multiDomain} autoSize={{ minRows: 1, maxRows: 2 }} placeholder={assetT('advancedFilters.multiDomainPlaceholder')} onChange={(event) => updateFilterDraft({ multiDomain: event.target.value })} />
      : key === 'user' || key === 'certificateID'
        ? <IdOrNameInput aria-label={assetT(`advancedFilters.${key}`)} value={filterDraft[key]} placeholder={assetT(`advancedFilters.${key}Placeholder`)}
          freeText={key === 'user'} isId={(text) => /^\d+$/.test(text)} search={key === 'user' ? ownerSearch : certificateIDSearch}
          onChange={(next) => updateFilterDraft({ [key]: next })} />
        : <Input aria-label={assetT(`advancedFilters.${key}`)} value={filterDraft[key]} placeholder={assetT(`advancedFilters.${key}Placeholder`)} onChange={(event) => updateFilterDraft({ [key]: event.target.value })} />,
  })
  const selectFilter = <K extends 'type' | 'dnsApi' | 'expiresAt' | 'enabled' | 'issueStatus' | 'syncStatus'>(key: K, options: Array<{ value: string; label: string }>, placeholder: string): AdvancedFilterItem => ({
    key,
    label: assetT(`advancedFilters.${key}`),
    applied: appliedFilters[key] ? options.find((option) => option.value === appliedFilters[key])?.label ?? appliedFilters[key] : undefined,
    field: <Select allowClear aria-label={assetT(`advancedFilters.${key}`)} value={filterDraft[key]} placeholder={placeholder} options={options}
      onChange={(value) => updateFilterDraft({ [key]: value } as Partial<CertificateFilterDraft>)} />,
  })
  const advancedItems: AdvancedFilterItem[] = [
    textFilter('domain'), textFilter('multiDomain'), textFilter('user'), textFilter('certificateID'), textFilter('name'), textFilter('remark'),
    selectFilter('type', typeOptions, assetT('advancedFilters.selectPlaceholder')),
    selectFilter('dnsApi', dnsApiOptions, assetT('advancedFilters.selectPlaceholder')),
    selectFilter('expiresAt', expiresOptions, assetT('advancedFilters.selectPlaceholder')),
    selectFilter('enabled', enabledOptions, assetT('advancedFilters.unrestricted')),
    selectFilter('issueStatus', issueOptions, assetT('advancedFilters.unrestricted')),
    selectFilter('syncStatus', syncOptions, assetT('advancedFilters.unrestricted')),
  ]

  return (
    <div className="certificate-page-inner">
      <Form form={form} component={false} />
      <Form form={uploadForm} component={false} />
      <Form form={bindForm} component={false} />
      <div className="certificate-section-tabs" role="tablist" aria-label={t('outerTabs.label')}>
        <button type="button" role="tab" aria-selected={sectionTab === 'list'} className={sectionTab === 'list' ? 'is-active' : ''} onClick={() => { setSectionTab('list'); onSectionChange?.('list') }}>
          {t('outerTabs.list')}
        </button>
        <button type="button" role="tab" aria-selected={sectionTab === 'default'} className={sectionTab === 'default' ? 'is-active' : ''} onClick={() => { setSectionTab('default'); onSectionChange?.('default') }}>
          {t('outerTabs.default')}
        </button>
        <button type="button" role="tab" aria-selected={sectionTab === 'dnsApi'} className={sectionTab === 'dnsApi' ? 'is-active' : ''} disabled={!canReadDNS} onClick={() => { setSectionTab('dnsApi'); onSectionChange?.('dnsApi') }}>
          {t('outerTabs.dnsApi')}
        </button>
      </div>
      <div className={`certificate-section-content${sectionTab === 'list' ? '' : ' certificate-list-hidden'}`}>
      <div className="identity-toolbar certificate-toolbar">
        <AdvancedFilters
          className="certificate-advanced-filters"
          storageKey="certificate-list"
          columns={4}
          onOpenChange={setAdvancedFilterOpen}
          primary={<>
            <h1 id="certificate-list-title">{t('title')}</h1>
            {canManage && activeTab === 'assets' ? <Button type="primary" icon={<Plus size={15} />} disabled={addLocked} onClick={openAdd}>{assetT('assetActions.add')}</Button> : null}
            {activeTab === 'assets' ? <>
              {(() => {
                const blocked = selectedRow ? reapplyBlock(selectedRow) : null
                const button = <Button disabled={!selectedRow?.version || blocked !== null} onClick={() => { if (selectedRow) openReapply(selectedRow) }}>{assetT('assetActions.reapply')}</Button>
                return blocked ? <Tooltip title={blocked}><span className="certificate-blocked-action">{button}</span></Tooltip> : button
              })()}
              {/* 表头“更多操作”只放批量动作，单张操作在行内“更多”。 */}
              <Dropdown
                trigger={['click']}
                disabled={bulkMutation.isPending}
                menu={{
                  items: [
                    ...(canManage ? [
                      { key: 'enable', label: assetT('assetActions.enable'), disabled: selectedAssets.length === 0 },
                      { key: 'disable', label: assetT('assetActions.disable'), disabled: selectedAssets.length === 0 },
                      { key: 'download', label: assetT('assetActions.download'), disabled: selectedAssets.length === 0 },
                      { key: 'enableAutoRenew', label: assetT('assetActions.enableAutoRenew'), disabled: selectedAssets.length === 0 },
                      { key: 'disableAutoRenew', label: assetT('assetActions.disableAutoRenew'), disabled: selectedAssets.length === 0 },
                      { key: 'delete', danger: true, label: assetT('assetActions.delete'), disabled: selectedAssets.length === 0 },
                    ] : []),
                    { key: 'orders', label: assetT('assetActions.orders') },
                    { key: 'clear', label: assetT('assetActions.clearSelection'), disabled: selectedAssetIDs.length === 0 },
                  ],
                  onClick: ({ key }) => {
                    if (key === 'orders') { openOrders(); return }
                    if (key === 'clear') { setSelectedAssetIDs([]); return }
                    runBulk(key as BulkAction)
                  },
                }}
              >
                <Button>{assetT('assetActions.more')} <MoreHorizontal size={13} /></Button>
              </Dropdown>
            </> : null}
            {activeTab === 'orders' ? <Button icon={<ArrowLeft size={15} />} onClick={closeOrders}>{assetT('assetActions.backToList')}</Button> : null}
            {canManage && activeTab === 'orders' ? <Button type="primary" icon={<Plus size={15} />} disabled={addLocked} onClick={openRequest}>{t('actions.create')}</Button> : null}
            <div className="identity-search">
              {activeTab === 'assets' ? <Select aria-label={assetT('assetColumns.domains')} value="domains" disabled options={[{ value: 'domains', label: assetT('assetColumns.domains') }]} /> : null}
              <Input
                type="search"
                allowClear
                value={searchDraft}
                aria-label={activeTab === 'assets' ? assetT('assetActions.search') : t('actions.search')}
                placeholder={activeTab === 'assets' ? assetT('assetActions.search') : t('actions.search')}
                onChange={(event) => setSearchDraft(event.target.value)}
              />
            </div>
          </>}
          items={activeTab === 'assets' ? advancedItems : []}
          queryText={assetT('assetActions.searchSubmit')}
          onQuery={() => applyAdvancedFilters(filterDraft)}
          onReset={() => { setSearchDraft(''); setSearch(''); resetAdvancedFilters() }}
          onClearAdvanced={() => applyAdvancedFilters(emptyFilterDraft)}
          onRemove={(key) => applyAdvancedFilters({ ...filterDraft, [key]: key in emptyFilterDraft ? '' : undefined })}
          extra={<>
            {activeTab === 'assets' ? <Button icon={<Download size={14} />} disabled={filteredAssetRows.length === 0} onClick={exportAssets}>{assetT('assetActions.export')}</Button> : null}
            <Button icon={<RefreshCw size={14} />} aria-label={assetT('actions.refresh')} onClick={() => {
              if (currentSessionAccess('certificates.read')) void (activeTab === 'assets' ? assetsQuery.refetch() : query.refetch())
            }} />
          </>}
        />
      </div>
      {activeTab === 'orders' ? (
        <div className="certificate-orders-heading">
          <strong>{assetT('orders.title')}</strong>
          <span>{orderAsset ? assetT('orders.scoped', { domains: orderAsset.sans.join(', ') || assetT('assetValues.loading') }) : assetT('orders.all')}</span>
        </div>
      ) : null}
		{activeTab === 'assets' ? (
          <div className="certificate-status-bar" aria-label={assetT('stats.label')}>
            <div className="certificate-status-pills">
              {([
                ['all', assetStats.all],
                ['normal', assetStats.normal],
                ['expiring', assetStats.expiring],
                ['expired', assetStats.expired],
                ['autoRenew', assetStats.autoRenew],
                ['manualRenew', assetStats.manualRenew],
              ] as const).map(([key, count]) => (
                <button key={key} type="button" className={assetFilter === key ? 'is-active' : ''} aria-pressed={assetFilter === key}
                  onClick={() => { setAssetFilter(key); setPage(1); setSelectedAssetIDs([]) }}>
                  <span>{assetT(`filters.${key}`)}</span><strong>{count}</strong>
                </button>
              ))}
            </div>
          </div>
        ) : null}
		{accepted ? <Alert className="identity-alert" type="success" showIcon closable message={t('editor.acceptedTitle')} description={t('editor.acceptedDescription')} onClose={() => setAccepted(false)} /> : null}
		{detailError ? <FeedbackWhen title={errorMessage(detailError, activeTab === 'assets' ? assetT : t)} onClose={() => setDetailError(null)} /> : null}
      {activeError ? <FeedbackWhen title={activeTab === 'assets' ? assetT('errors.assetsLoadFailed') : t('errors.loadFailed')} detail={queryError ? errorMessage(queryError, activeTab === 'assets' ? assetT : t) : (activeTab === 'assets' ? assetT('errors.request_failed') : t('errors.request_failed'))} action={<Button size="small" onClick={() => {
        if (currentSessionAccess('certificates.read')) void (activeTab === 'assets' ? assetsQuery.refetch() : query.refetch())
      }}>{assetT('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll" data-testid="certificate-table-scroll" aria-busy={activeTab === 'assets' ? assetsQuery.isFetching : query.isFetching}>
        {activeTab === 'assets' ? (
          <Table
            rowKey={(row) => row.asset.id} size="small" columns={assetColumns} dataSource={filteredAssetRows}
            loading={assetsQuery.isPending || assetsQuery.isFetching} pagination={false}
            locale={{ emptyText: assetsQuery.isPending ? ' ' : assetT(hasActiveAssetFilter ? 'assetValues.filteredEmpty' : 'assetValues.empty') }}
            rowSelection={{
              columnWidth: certificateColumnWidths.assets.selection,
              selectedRowKeys: selectedAssetIDs,
              onChange: (keys) => setSelectedAssetIDs(keys.map(String)),
            }}
            tableLayout="fixed"
            scroll={{ x: certificateTableWidth(certificateColumnWidths.assets, isTenant ? ['user'] : []) }}
          />
        ) : (
          <Table
            rowKey="id" size="small" columns={columns} dataSource={pageItems}
            loading={query.isPending || query.isFetching} pagination={false}
            locale={{ emptyText: query.isPending ? ' ' : t(search.trim() ? 'values.filteredEmpty' : 'values.empty') }}
            tableLayout="fixed"
            scroll={{ x: certificateTableWidth(certificateColumnWidths.orders) }}
          />
        )}
      </div>
      <div className="identity-pagination">
        <Pagination
          current={page}
          pageSize={limit}
		  total={activeTab === 'assets' ? (assetsQuery.data?.total ?? 0) : filtered.length}
          showSizeChanger
          pageSizeOptions={[10, 20, 50]}
          showTotal={(total) => t('values.total', { count: total })}
          onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }}
        />
      </div>
      </div>
      {sectionTab === 'default' ? (
        <div className="certificate-section-content certificate-default-panel">
          {defaultsQuery.error ? <FeedbackWhen title={t('defaultSettings.loadFailed')} action={<Button size="small" onClick={() => void defaultsQuery.refetch()}>{t('defaultSettings.retry')}</Button>} /> : null}
          {defaultWriteError && !refusedDefault ? <FeedbackWhen title={errorMessage(defaultWriteError, t)} action={defaultWriteError.code === 'version_conflict' ? <Button size="small" onClick={() => void defaultsQuery.refetch()}>{t('defaultSettings.retry')}</Button>
            : defaultsUncertain ? <Button size="small" loading={defaultsMutation.isPending} onClick={() => { if (currentSessionAccess('certificates.manage')) defaultsMutation.mutate() }}>{assetT('actions.retrySameRequest')}</Button> : undefined} /> : null}
          <div className="certificate-default-field">
            <label htmlFor="certificate-default-user">{t('defaultSettings.user')}</label>
            {targetSelector ? targetSelector(defaultsLocked) : targetUser ? (
              <Input
                id="certificate-default-user"
                value={`${targetUser.username}（ID: ${targetUser.displayID ?? targetUser.id}）`}
                disabled
                aria-label={t('defaultSettings.user')}
              />
            ) : null}
          </div>
          <div className="certificate-default-field">
            <label htmlFor="certificate-default-type">{t('defaultSettings.certificateType')}</label>
            <Select
              id="certificate-default-type"
              disabled={!targetUser || defaultsLocked}
              value={defaultType}
              placeholder={targetUser ? t('defaultSettings.certificateTypePlaceholder') : t('defaultSettings.selectUserFirst')}
              aria-label={t('defaultSettings.certificateType')}
              options={[
                { value: 'acme', label: t('defaultSettings.certificateTypeAutomatic') },
                { value: 'uploaded', label: t('defaultSettings.certificateTypeUploaded') },
              ]}
              status={defaultFieldStatus('certificate_type')}
              onChange={(value: CertificateDefaultType) => { editDefault(); setDefaultType(value); if (value === 'uploaded') { setDefaultProviderID(undefined); setDefaultIssuer(undefined) } }}
            />
            {defaultFieldHelp('certificate_type')}
          </div>
          {issuerOptions.length > 1 ? <div className="certificate-default-field">
            <label htmlFor="certificate-default-issuer">{t('defaultSettings.issuer')}</label>
            <Select
              id="certificate-default-issuer" allowClear aria-label={t('defaultSettings.issuer')}
              value={defaultIssuer} placeholder={t('defaultSettings.issuerPlatform')}
              options={issuerOptions} onChange={(value: CertificateIssuer | undefined) => { editDefault(); setDefaultIssuer(value) }}
              disabled={!targetUser || defaultType !== 'acme' || defaultsLocked} status={defaultFieldStatus('issuer')}
            />
            {defaultFieldHelp('issuer')}
          </div> : null}
          <div className="certificate-default-field">
            <label htmlFor="certificate-default-dns">{t('defaultSettings.dnsApi')}</label>
            {targetUser && canReadDNS ? (
              <Select
                id="certificate-default-dns"
                allowClear
                value={defaultProviderID}
                placeholder={t('defaultSettings.dnsApiPlaceholder')}
                aria-label={t('defaultSettings.dnsApi')}
                loading={providersQuery.isPending || providersQuery.isFetching}
                options={providerItems.filter((item) => item.managed_by !== 'platform').map((item) => ({ value: item.id, label: item.name }))}
                onChange={(value: string | undefined) => { editDefault(); setDefaultProviderID(value) }}
                disabled={defaultType !== 'acme' || defaultsLocked} status={defaultFieldStatus('dns_provider_id')}
              />
            ) : (
              <span className="certificate-default-hint">{t('defaultSettings.dnsApiSelectUser')}</span>
            )}
            {defaultFieldHelp('dns_provider_id')}
          </div>
          {canManageEAB ? <section className="certificate-default-eab" aria-labelledby="certificate-default-eab-title">
            <h3 id="certificate-default-eab-title">{t('eabSettings.title')}</h3>
            <p>{t('eabSettings.description')}</p>
            <AcmeCACredentialsCard t={systemT} editable />
          </section> : null}
          {canManage ? <div className="certificate-default-actions"><Button type="primary" loading={defaultsMutation.isPending} disabled={!targetUser || defaultsQuery.isPending || defaultsQuery.isError || defaultsLocked} onClick={saveCertificateDefaults}>{t('defaultSettings.save')}</Button>{defaultsQuery.data?.updated_at ? <span className="certificate-default-saved">{t('defaultSettings.updatedAt', { value: formatDateTime(defaultsQuery.data.updated_at, i18n.language) })}</span> : null}</div> : null}
        </div>
      ) : null}
      {sectionTab === 'dnsApi' ? (
        <div className="certificate-section-content certificate-dns-panel">
          {targetSelector ? <div className="certificate-default-field"><label>{assetT('target.label')}</label>{targetSelector(providerWritesLocked)}</div> : null}
          <div className="certificate-dns-toolbar">
            <Space wrap>
              {canManageDNS ? <Button type="primary" icon={<Plus size={15} />} disabled={providerWritesLocked || !targetUser} onClick={() => {
                setProviderWriteError(null)
                setProviderEditor({ mode: 'create' })
              }}>{t('dnsApi.actions.create')}</Button> : null}
              {canManageDNS ? (
                <Popconfirm
                  title={t('dnsApi.confirmDeleteSelected')}
                  okText={t('dnsApi.actions.delete')}
                  cancelText={t('dnsApi.actions.cancel')}
                  okButtonProps={{ danger: true }}
                  onConfirm={() => void deleteSelectedProviders()}
                >
                  <Button danger disabled={providerWritesLocked || selectedProviderIDs.length === 0}>{t('dnsApi.actions.deleteSelected')}</Button>
                </Popconfirm>
              ) : null}
            </Space>
            <span className="certificate-dns-total">{t('dnsApi.total', { count: providerItems.length })}</span>
          </div>
          {providerUncertain && !providerEditor ? (
            <OutcomeUnknown title={dnsT('uncertainty.title')} detail={dnsT('uncertainty.description')} action={<Space size={4}>
                <Button size="small" loading={providerMutation.isPending} onClick={() => providerMutation.mutate()}>{dnsT('actions.retrySameRequest')}</Button>
                <Button size="small" onClick={closeProviderAndRefresh}>{dnsT('actions.closeAndRefresh')}</Button>
              </Space>} className="identity-alert" />
          ) : providerWriteError && !providerEditor ? (
            <FeedbackWhen title={errorMessage(providerWriteError, dnsT)} onClose={() => setProviderWriteError(null)} />
          ) : null}
          {providersQuery.error ? (
            <FeedbackWhen title={dnsT('errors.loadFailed')} detail={providersQuery.error instanceof ApiError ? errorMessage(providersQuery.error, dnsT) : dnsT('errors.request_failed')} action={<Button size="small" onClick={() => {
                if (currentSessionAccess('dns.read')) void providersQuery.refetch()
              }}>{dnsT('actions.retry')}</Button>} />
          ) : null}
          <div className="identity-table-scroll" aria-busy={providersQuery.isFetching}>
            <Table
              rowKey="id" size="small" columns={certificateProviderColumns} dataSource={providerPageItems}
              loading={Boolean(targetUser) && (providersQuery.isPending || providersQuery.isFetching)} pagination={false}
              locale={{ emptyText: !targetUser ? assetT('target.required') : providersQuery.isPending ? ' ' : t('dnsApi.empty') }}
              rowSelection={canReadDNS ? {
                selectedRowKeys: selectedProviderIDs,
                onChange: (keys) => setSelectedProviderIDs(keys.map(String)),
              } : undefined}
              scroll={{ x: 1120 }}
            />
          </div>
          <div className="identity-pagination certificate-dns-pagination">
            <Pagination
              current={providerPage}
              pageSize={providerLimit}
              total={providerItems.length}
              showSizeChanger
              pageSizeOptions={[10, 20, 50]}
              showTotal={(total) => t('dnsApi.total', { count: total })}
              onChange={(nextPage, nextLimit) => {
                setProviderPage(nextLimit === providerLimit ? nextPage : 1)
                setProviderLimit(nextLimit)
              }}
            />
          </div>
          <ProviderEditor
            sectioned
            editor={providerEditor}
            isAdmin={false}
            pending={providerMutation.isPending}
            uncertain={providerUncertain}
            error={providerEditor ? providerWriteError : null}
            onCancel={() => {
              if (!providerWritesLocked) {
                clearProviderWriteCredentials(providerAttemptRef.current)
                providerAttemptRef.current = null
                setProviderAttempt(null)
                setProviderWriteError(null)
                setProviderEditor(null)
              }
            }}
            onSubmit={submitProviderEditor}
            onRetry={() => providerMutation.mutate()}
            onCloseAndRefresh={closeProviderAndRefresh}
          />
        </div>
      ) : null}
		<Modal
		  className="identity-modal" title={assetT('detail.title')} open={detail !== null} width={820}
		  footer={<Space>
			{canManage ? <Button disabled={commandLocked || !detail?.versions.some((item) => item.status === 'active')} onClick={openBind}>{assetT('assetActions.bind')}</Button> : null}
			<Button disabled={canManage && commandLocked} onClick={() => { setDetail(null); setBindings([]); setCommandError(null) }}>{assetT('assetActions.close')}</Button>
		  </Space>}
		  closable={!canManage || !commandLocked} maskClosable={!canManage || !commandLocked} keyboard={!canManage || !commandLocked}
		  onCancel={() => { if (!canManage || !commandLocked) { setDetail(null); setBindings([]); setCommandError(null) } }} destroyOnHidden
		>
		  {detail ? (
			<>
			  {commandAlert}
			  <Space size="large" wrap>
              <span>{assetT('detail.name')}: {detail.asset.name}</span>
              <span>{assetT('detail.source')}: {assetT(`assetSources.${detail.asset.source}`)}</span>
              <span>{assetT('detail.revision')}: {detail.asset.revision}</span>
            </Space>
            <Table
				className="identity-table-scroll" rowKey="id" size="small" columns={versionColumns}
				dataSource={detail.versions} pagination={false} scroll={{ x: 730 }}
				locale={{ emptyText: assetT('assetValues.noVersions') }}
			  />
			  <Table
				className="identity-table-scroll" rowKey="site_id" size="small" columns={bindingColumns}
				dataSource={bindings} pagination={false} scroll={{ x: 580 }}
				locale={{ emptyText: assetT('assetValues.noBindings') }}
			  />
			</>
		  ) : null}
		</Modal>
		<Modal
		  className="identity-modal" title={assetT('bind.title')} open={canManage && bindTarget !== null}
		  okText={commandUncertain ? assetT('actions.retrySameRequest') : assetT('bind.confirm')}
		  cancelText={assetT('actions.cancel')} confirmLoading={commandMutation.isPending}
		  cancelButtonProps={{ disabled: commandLocked }} closable={!commandLocked}
		  maskClosable={!commandLocked} keyboard={!commandLocked}
		  onCancel={() => { if (!commandLocked) { commandAttemptRef.current = null; setCommandAttempt(null); setBindTarget(null); setCommandError(null); bindForm.resetFields() } }}
		  onOk={() => commandUncertain
			? commandAttempt && currentSessionAccess('certificates.manage') && commandMutation.mutate()
			: void bindForm.validateFields().then(submitBind).catch(() => undefined)}
		  destroyOnHidden
		>
		  {commandAlert}
		  <Form form={bindForm} layout="vertical" requiredMark={false} disabled={commandLocked}>
			<Form.Item name="site_id" label={assetT('bind.site')} extra={assetT('bind.siteHint')} rules={[
			  { required: true, message: assetT('bind.siteRequired') },
			  { pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, message: assetT('bind.siteInvalid') },
			]}>
			  <CertificateSiteSelect
			    ownerID={queryOwner[0] === 'platform' ? bindTarget?.asset.owner?.id : undefined}
			    sans={bindTarget?.version.sans ?? []}
			  />
			</Form.Item>
			<Form.Item name="version_id" label={assetT('bind.version')} hidden><Input /></Form.Item>
			<Form.Item name="default" label={assetT('bind.default')} valuePropName="checked"><Switch /></Form.Item>
		  </Form>
		</Modal>
		<Modal
		  className="identity-modal" title={assetT('reapply.title')} open={canManage && reapplyTarget !== null}
		  okText={assetT('reapply.confirm')} cancelText={assetT('actions.cancel')}
		  confirmLoading={mutation.isPending} okButtonProps={{ disabled: uncertain }} cancelButtonProps={{ disabled: mutation.isPending }}
		  closable={!mutation.isPending} maskClosable={!mutation.isPending} keyboard={!mutation.isPending}
		  onCancel={() => { if (!mutation.isPending) { orderAttemptRef.current = null; setAttempt(null); setWriteError(null); setReapplyTarget(null) } }}
		  onOk={() => {
			if (!reapplyTarget || !currentSessionAccess('certificates.manage')) return
			const next = orderAttemptFor(reapplyTarget.input)
			orderAttemptRef.current = next
			setAttempt(next)
			setWriteError(null)
			mutation.mutate()
		  }}
		  destroyOnHidden
		>
		  {reapplyTarget ? <p>{assetT('reapply.description', { name: reapplyTarget.name, domains: reapplyTarget.input.domains.join('、') })}</p> : null}
		  {reapplyTarget && writeError ? <Alert className="identity-alert" type={uncertain ? 'warning' : 'error'} showIcon
			message={uncertain ? t('uncertainty.title') : errorMessage(writeError, t)}
			description={uncertain ? undefined : assetT('reapply.retryHint')} /> : null}
		</Modal>
		<Modal
		  className="identity-modal" title={assetT('delete.title')} open={canManage && deleteTarget !== null}
		  okText={commandUncertain ? assetT('actions.retrySameRequest') : assetT('delete.confirm')}
		  okButtonProps={{ danger: true }} cancelText={assetT('actions.cancel')}
		  confirmLoading={commandMutation.isPending} cancelButtonProps={{ disabled: commandLocked }}
		  closable={!commandLocked} maskClosable={!commandLocked} keyboard={!commandLocked}
		  onCancel={() => { if (!commandLocked) { commandAttemptRef.current = null; setCommandAttempt(null); setDeleteTarget(null); setCommandError(null) } }}
		  onOk={() => {
			if (commandUncertain) {
			  if (commandAttempt && currentSessionAccess('certificates.manage')) commandMutation.mutate()
			} else if (deleteTarget) {
			  startCommand({ kind: 'delete', asset: deleteTarget, key: writeKey(), requestID: requestID() })
			}
		  }}
		  destroyOnHidden
		>
		  {commandAlert}
		  <Alert type="warning" showIcon message={assetT('delete.description', { name: deleteTarget?.name ?? '' })} />
      </Modal>
      <Modal
        className="identity-modal certificate-add-modal" width={720}
        title={requestOnly ? t('editor.title') : assetT('assetActions.add')}
        open={canManage && addOpen}
        closable={!addLocked} maskClosable={!addLocked} keyboard={!addLocked}
        onCancel={closeAdd}
        footer={batchOpen ? (batchStarted ? <Space>
          {batchRetryable ? <Button disabled={batchRunning} onClick={() => void runBatch()}>{t('batch.retryFailed')}</Button> : null}
          <Button type="primary" disabled={batchRunning} loading={batchRunning} onClick={closeAdd}>{t('batch.close')}</Button>
        </Space> : <Space>
          <Button onClick={closeAdd}>{t('actions.cancel')}</Button>
          <Button type="primary" onClick={() => void batchForm.validateFields().then(submitBatch).catch(() => undefined)}>{t('editor.save')}</Button>
        </Space>) : <Space>
          <Button disabled={addLocked} onClick={closeAdd}>{t('actions.cancel')}</Button>
          <Button type="primary" loading={uploadOpen ? uploadMutation.isPending : mutation.isPending} onClick={() => {
            if (uploadOpen) {
              if (assetUncertain) { if (assetAttempt && currentSessionAccess('certificates.manage')) uploadMutation.mutate() }
              else void uploadForm.validateFields().then(submitUpload).catch(() => undefined)
            } else if (uncertain) {
              if (attempt && currentSessionAccess('certificates.manage')) mutation.mutate()
            } else void form.validateFields().then(submit).catch(() => undefined)
          }}>{(uploadOpen ? assetUncertain : uncertain) ? t('actions.retrySameRequest') : requestOnly ? t('actions.submit') : t('editor.save')}</Button>
        </Space>}
        destroyOnHidden
      >
        {!requestOnly ? <div className="certificate-section-tabs certificate-add-tabs" role="tablist" aria-label={assetT('assetActions.add')}>
          <button type="button" role="tab" aria-selected={!batchOpen} className={!batchOpen ? 'is-active' : ''} disabled={addLocked || batchStarted} onClick={() => chooseAddTab('single')}>{t('batch.single')}</button>
          <button type="button" role="tab" aria-selected={batchOpen} className={batchOpen ? 'is-active' : ''} disabled={addLocked} onClick={() => chooseAddTab('batch')}>{t('batch.tab')}</button>
        </div> : null}
        {uploadOpen ? <>
            {assetWriteError ? (
              <Alert
                className="identity-alert" type={assetUncertain ? 'warning' : 'error'} showIcon
                message={assetUncertain ? assetT('assetUncertainty.title') : errorMessage(assetWriteError, assetT)}
                description={assetUncertain ? assetT('assetUncertainty.description') : undefined}
                action={assetUncertain ? <Button size="small" onClick={() => {
                  uploadAttemptRef.current = null; uploadForm.resetFields(); setUploadOpen(false); setAssetAttempt(null); setAssetWriteError(null)
                  if (currentSessionAccess('certificates.read')) void assetsQuery.refetch()
                }}>{assetT('actions.closeAndRefresh')}</Button> : undefined}
              />
            ) : null}
        </> : batchOpen ? <>
          {writeError ? <Alert className="identity-alert" type="error" showIcon message={errorMessage(writeError, t)} /> : null}
        </> : <>
            {writeError && !orderFieldMarked ? (
              <Alert
                className="identity-alert"
                type={uncertain ? 'warning' : 'error'}
                showIcon
                message={uncertain ? t('uncertainty.title') : errorMessage(writeError, t)}
                description={uncertain ? t('uncertainty.description') : undefined}
                action={uncertain ? <Button size="small" onClick={() => {
                  orderAttemptRef.current = null; setAttempt(null); setWriteError(null); setEditorOpen(false)
                  if (currentSessionAccess('certificates.read')) void query.refetch()
                }}>{t('actions.closeAndRefresh')}</Button> : undefined}
              />
            ) : null}
        </>}
        {queryOwner[0] === 'platform' && !reapplyScopeID && siteOwner && !uploadOpen ? <div className="certificate-add-owner">
          <span>{assetT('target.label')}</span>
          <Input readOnly aria-label={assetT('target.label')} value={siteOwner.label} />
          <small>{assetT('target.fromSite')}</small>
        </div> : null}
        {queryOwner[0] === 'platform' && !reapplyScopeID && !(siteOwner && !uploadOpen) ? <div className="certificate-add-owner">
          <span>{uploadOpen ? assetT('upload.owner') : assetT('target.label')}</span>
          <CertificateOwnerPicker owner={queryOwner} value={uploadOpen ? uploadOwner : orderOwner} disabled={addLocked || batchStarted}
            label={uploadOpen ? assetT('upload.owner') : assetT('target.label')}
            onChange={(value) => {
              if (uploadOpen) { setUploadOwner(value); setAssetWriteError(null); return }
              setOrderOwner(value); setWriteError(null)
              if (batchOpen) batchForm.setFieldValue('dns_provider_id', undefined)
              else form.setFieldValue('dns_provider_id', undefined)
            }} />
        </div> : null}
        {!requestOnly || offeredIssuers.length > 1 ? <section className="certificate-type-section" aria-label={t('batch.type')}>
          <h3>{t('batch.type')}<small>{t('batch.typeHint')}</small></h3>
          <div className="certificate-type-cards">
            {!requestOnly && !batchOpen ? <button type="button" className={`certificate-type-card${uploadOpen ? ' is-active' : ''}`} aria-pressed={uploadOpen}
              disabled={addLocked} onClick={chooseUpload}>
              <strong>{t('batch.uploadType')}</strong><span>{t('batch.uploadTypeHint')}</span>
            </button> : null}
            {shownIssuerCards.map((issuer) => {
              const unconfigured = issuer === 'zerossl' && zeroSSLUnconfigured
              const active = !uploadOpen && !unconfigured && selectedIssuer === issuer
              const card = <button key={issuer} type="button" className={`certificate-type-card${active ? ' is-active' : ''}`} aria-pressed={active}
                aria-describedby={unconfigured ? 'certificate-zerossl-unconfigured' : undefined}
                disabled={addLocked || batchStarted || unconfigured} onClick={() => chooseIssuer(issuer)}>
                <strong>{t(`issuers.${issuer}`)}</strong>
                <span id={unconfigured ? 'certificate-zerossl-unconfigured' : undefined}>
                  {unconfigured ? t('batch.zerosslUnconfigured') : t(`batch.issuerHints.${issuer}`)}
                </span>
              </button>
              return card
            })}
          </div>
          {zeroSSLUnconfigured && !requestOnly && canManageEAB ? <div className="certificate-type-note">
            {t('batch.zerosslUnconfiguredAdmin')}
            <Button type="link" size="small" onClick={openEABSettings}>{t('batch.zerosslConfigure')}</Button>
          </div> : null}
        </section> : null}
        {uploadOpen ? <>
            <Form key="upload" form={uploadForm} layout="vertical" requiredMark={false} disabled={assetWritesLocked}>
              <Form.Item name="name" label={assetT('upload.name')} rules={[
                { required: true, whitespace: true, message: assetT('upload.nameRequired') },
                {
                  validator: (_, value?: string) => {
                    if (value && 128 < utf8ByteLength(value.trim())) {
                      return Promise.reject(new Error(assetT('upload.nameInvalid')))
                    }
                    return Promise.resolve()
                  },
                },
              ]}>
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="remark" label={assetT('upload.remark')} rules={[{ max: 256, message: assetT('upload.remarkInvalid') }]}>
                <Input autoComplete="off" placeholder={assetT('upload.remarkPlaceholder')} />
              </Form.Item>
              <Form.Item name="certificate_pem" label={assetT('upload.certificatePem')} rules={[{ required: true, whitespace: true, message: assetT('upload.certificateRequired') }]}>
                <Input.TextArea rows={7} autoComplete="off" spellCheck={false} />
              </Form.Item>
              <PEMFileButton kind="certificate" disabled={assetWritesLocked} current={() => uploadForm.getFieldValue('certificate_pem')} onRead={(text) => uploadForm.setFields([{ name: 'certificate_pem', value: text, errors: [] }])}
                onError={(error) => uploadForm.setFields([{ name: 'certificate_pem', errors: [assetT(`upload.fileErrors.${error}`)] }])} />
              <Form.Item name="private_key_pem" label={assetT('upload.privateKeyPem')} rules={[{ required: true, whitespace: true, message: assetT('upload.privateKeyRequired') }]}>
                <Input.TextArea rows={7} autoComplete="off" spellCheck={false} />
              </Form.Item>
              <PEMFileButton kind="privateKey" disabled={assetWritesLocked} current={() => uploadForm.getFieldValue('private_key_pem')} onRead={(text) => uploadForm.setFields([{ name: 'private_key_pem', value: text, errors: [] }])}
                onError={(error) => uploadForm.setFields([{ name: 'private_key_pem', errors: [assetT(`upload.fileErrors.${error}`)] }])} />
              <Alert type="warning" showIcon message={assetT('upload.privateKeyNotice')} />
            </Form>
        </> : batchOpen ? <>
          <Form key="batch" form={batchForm} layout="vertical" requiredMark={false} disabled={batchStarted}>
            <Form.Item name="lines" label={t('batch.lines')} extra={t('batch.linesExtra', { count: batchLineLimit })}
              rules={[{ required: true, whitespace: true, message: t('batch.linesRequired') }]}>
              <Input.TextArea rows={5} placeholder={t('batch.linesPlaceholder')} spellCheck={false} />
            </Form.Item>
            {!canReadDNS ? <Alert className="identity-alert" type="warning" showIcon message={t('editor.dnsPermissionRequired')} /> : null}
            {canReadDNS && providersQuery.isSuccess && usableProviders.length === 0 ? <Alert className="identity-alert" type="info" showIcon message={t('editor.noDNSProvider')}
              action={<Button size="small" type="link" disabled={batchStarted} onClick={() => { closeAdd(); setSectionTab('dnsApi'); onSectionChange?.('dnsApi') }}>{assetT('dnsProvider.configure')}</Button>} /> : null}
            <Form.Item name="dns_provider_id" label={t('editor.dnsProvider')} extra={t('batch.dnsExtra')}>
              <Select allowClear loading={providersQuery.isPending && providersQuery.fetchStatus !== 'idle'} placeholder={t('editor.dnsProviderPlaceholder')}
                options={usableProviders.map((item) => ({ value: item.id, label: item.name }))} />
            </Form.Item>
          </Form>
          {batchStarted ? <Table<BatchRow>
            className="identity-table-scroll certificate-batch-results" rowKey="line" size="small" pagination={false}
            dataSource={batchRows} scroll={{ x: 560 }}
            columns={[
              { title: t('batch.columns.line'), dataIndex: 'line', width: 64 },
              { title: t('batch.columns.domains'), key: 'domains', render: (_, row) => row.domains.join(' ') },
              { title: t('batch.columns.status'), key: 'status', width: 120, render: (_, row) => <Tag color={
                row.status === 'accepted' ? 'success' : row.status === 'failed' ? 'error' : row.status === 'unknown' ? 'warning' : 'processing'
              }>{t(`batch.states.${row.status}`)}</Tag> },
              { title: t('batch.columns.reason'), key: 'reason', render: (_, row) => row.status === 'unknown'
                ? t('batch.unknownReason') : row.error ? errorMessage(row.error, t) : '' },
            ]}
          /> : null}
          {batchStarted && !batchRunning ? <Alert className="identity-alert" showIcon
            type={batchRetryable ? 'warning' : 'success'}
            message={t('batch.summary', {
              accepted: batchRows.filter((row) => row.status === 'accepted').length,
              failed: batchRows.filter((row) => row.status === 'failed' || row.status === 'unknown').length,
            })} /> : null}
        </> : <>
            <Form key="order" form={form} layout="vertical" requiredMark={false} disabled={writesLocked}>
              <Form.Item name="name" label={t('editor.name')} rules={[{ max: 128, message: t('validation.nameInvalid') }]}>
                <Input autoComplete="off" placeholder={t('editor.namePlaceholder')} />
              </Form.Item>
              <Form.Item name="remark" label={t('editor.remark')} rules={[{ max: 256, message: t('validation.remarkInvalid') }]}>
                <Input autoComplete="off" placeholder={t('editor.remarkPlaceholder')} />
              </Form.Item>
              <Form.Item
                name="domains_text"
                label={t('editor.domains')}
                extra={t('editor.domainsExtra')}
                rules={[{
                  validator: (_, value: string) => {
                    if (!value?.trim()) return Promise.reject(new Error(t('validation.domainsRequired')))
                    return normalizedDomains(value) ? Promise.resolve() : Promise.reject(new Error(t('validation.domainsInvalid')))
                  },
                }]}
              >
                <Input.TextArea rows={4} placeholder={t('editor.domainsPlaceholder')} />
              </Form.Item>
              <Form.Item name="challenge_type" label={t('editor.challenge')} rules={[{ required: true }]}>
                <Select
                  options={[
                    { value: 'dns-01', label: t('challenges.dns_01') },
                    { value: 'http-01', label: t('challenges.http_01_nodes') },
                  ]}
                  onChange={(value) => { if (value === 'http-01') form.setFieldValue('dns_provider_id', undefined) }}
                />
              </Form.Item>
              {challenge === 'http-01' ? <Alert className="identity-alert" type="info" showIcon message={t('editor.http01Hint')} /> : null}
              {challenge === 'dns-01' ? (
                <>
                  {!canReadDNS ? <Alert className="identity-alert" type="warning" showIcon message={t('editor.dnsPermissionRequired')} /> : null}
                  {providersQuery.isError ? <Alert className="identity-alert" type="error" showIcon message={t('errors.providersLoadFailed')} action={<Button size="small" onClick={() => {
                    if (currentSessionAccess('dns.read')) void providersQuery.refetch()
                  }}>{t('actions.retry')}</Button>} /> : null}
                  {canReadDNS && providersQuery.isSuccess &&
                    !providersQuery.data.items.some((item) => item.status !== 'disabled')
                    ? <Alert className="identity-alert" type="info" showIcon message={t('editor.noDNSProvider')}
                      action={<Button size="small" type="link" disabled={writesLocked} onClick={() => {
                        // 直接去本页“DNS API”配置（关闭弹窗）。
                        closeAdd(); setSectionTab('dnsApi'); onSectionChange?.('dnsApi')
                      }}>{assetT('dnsProvider.configure')}</Button>} /> : null}
                  <Form.Item
                    name="dns_provider_id"
                    label={t('editor.dnsProvider')}
                    rules={[{ required: true, message: t('validation.dnsProviderRequired') }]}
                  >
                    <Select
                      loading={providersQuery.isPending}
                      placeholder={t('editor.dnsProviderPlaceholder')}
                      options={usableProviders.map((item) => ({ value: item.id, label: item.name }))}
                    />
                  </Form.Item>
                </>
              ) : null}
              <Form.Item name="auto_renew" label={t('editor.autoRenew')} valuePropName="checked">
                <Switch />
              </Form.Item>
            </Form>
        </>}
      </Modal>
    </div>
  )
}
