import { useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, Badge, Button, Checkbox, Collapse, Descriptions, Drawer, Empty, Input, Modal, Result, Segmented, Select, Space, Spin, Table, Tag,
  type TableColumnsType,
} from 'antd'
import { ChevronLeft, ChevronRight, Eye, RefreshCw, Search, ShieldOff } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError, type Principal } from '../../api/auth'
import {
  newPluginInstallationIdempotencyKey,
  platformPluginInstallationsApi,
  pluginInstallationsApi,
  type PluginInstallation,
  type PluginInstallationApprovalInput,
  type PluginInstallationMutationResult,
  type PluginInstallationStatus,
} from '../../api/pluginInstallations'
import { useSessionStore } from '../../auth/session'
import { localizedUnknownApiError } from '../../i18n/apiError'
import { formatDateTime } from '../../i18n/formatters'
import { permissionName } from '../../i18n/permissionNames'
import '../../i18n/pluginInstallations'

import { AdvisoryList } from './AdvisoryList'
import { PluginIdentityKeyPanel } from './PluginIdentityKeyPanel'
import { SigningKeyPanel, UIPageDisclosure } from './PluginUIDisclosure'
import { useAdvisories } from './useAdvisories'
import { pluginName, usePluginCatalog } from './usePluginCatalog'

import './PluginMarketPage.css'
import { FeedbackWhen, OutcomeUnknown, PageSection } from '@cdnca/ui'

type ActionKind = 'confirm' | 'upgrade' | 'disable' | 'resume' | 'uninstall'

interface ActionSelection {
  kind: ActionKind
  installation: PluginInstallation
}

interface ActionAttempt extends ActionSelection {
  ownerKey: string
  key: string
  approval?: PluginInstallationApprovalInput
  reason?: string
}

interface ActionOutcome extends ActionSelection {
  installation: PluginInstallation
}

interface CursorState {
  key: string
  cursors: string[]
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

function ownerKey(principal: Principal, sessionEpoch: number): string {
  return JSON.stringify([principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch])
}

function currentTokenForManage(expectedOwnerKey: string, platform: boolean): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  if (platform) {
    return principal.scope_kind === 'platform' && `${ownerKey(principal, sessionEpoch)}:platform` === expectedOwnerKey &&
      principal.permissions.includes('plugin_installations.platform.manage') ? accessToken : null
  }
  if (principal.scope_kind !== 'tenant' || ownerKey(principal, sessionEpoch) !== expectedOwnerKey ||
    !(principal.permissions.includes('plugin_installations.manage') || principal.permissions.includes('platform.admin'))) return null
  return accessToken
}

function errorText(error: unknown, t: TFunction<'pluginInstallations'>): string {
  if (!(error instanceof ApiError)) return t('errors.request')
  switch (error.code) {
    case 'permission_denied':
    case 'forbidden': return t('errors.permissionDenied')
    case 'plugin_installation_not_found': return t('errors.notFound')
    case 'plugin_installation_revision_conflict': return t('errors.revisionConflict')
    case 'plugin_installation_idempotency_conflict': return t('errors.idempotencyConflict')
    case 'plugin_installation_scope_approval_required': return t('errors.scopeApproval')
    case 'plugin_installation_manifest_invalid': return t('errors.manifestInvalid')
    case 'plugin_installation_version_incompatible': return t('errors.versionIncompatible')
    case 'plugin_installation_platform_paused': return t('errors.platformPaused')
    case 'plugin_installation_license_unavailable': return t('errors.licenseUnavailable')
    case 'plugin_installation_result_unknown': return t('errors.resultUnknown')
    // The signed license answer was refused before anything changed here: retry the same action.
    case 'plugin_installation_activation_response_invalid': return localizedUnknownApiError(error, t('errors.activationResponseInvalid'))
    case 'invalid_response': return t('errors.invalidResponse')
    default: return localizedUnknownApiError(error, t('errors.request'))
  }
}

function unknownOutcome(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  // Refused before any local write: not an unknown outcome, the original action button retries it.
  if (error.code === 'plugin_installation_activation_response_invalid') return false
  return error.code === 'plugin_installation_result_unknown' || error.status === 0 || error.status === 408 || error.status >= 500
}

// The same attempt: owner, authorization, action and idempotency key (a callback never clears another one).
function sameAttempt(left: ActionAttempt, right: ActionAttempt): boolean {
  return left.ownerKey === right.ownerKey && left.installation.authorization_id === right.installation.authorization_id &&
    left.kind === right.kind && left.key === right.key
}

// What a permission lets the plugin do, for the known platform data-pack scopes (license-service
// plugin_data_pack.go); any other scope shows its stable ID only.
const scopePurposes = new Set(['platform.themes.provide', 'security.rule_packs.provide', 'dns.records.manage'])

// A plugin-specific purpose first, then the permission's display name; an unknown code shows the code only.
function ScopeLabel({ scope, t }: { scope: string; t: TFunction<'pluginInstallations'> }) {
  const purpose = scopePurposes.has(scope) ? t(`scopePurpose.${scope.replace(/\./g, '_')}`)
    : permissionName(scope) !== scope ? permissionName(scope) : null
  return purpose
    ? <span className="plugin-market-scope"><span>{purpose}</span> <code>{scope}</code></span>
    : <code>{scope}</code>
}

function statusColor(status: PluginInstallationStatus): string {
  if (status === 'enabled') return 'green'
  if (status === 'upgrade_failed_lkg_preserved') return 'orange'
  if (status === 'uninstalled') return 'default'
  if (status === 'pending_confirmation') return 'blue'
  return 'gold'
}

function stableReasonText(reason: string | null, t: TFunction<'pluginInstallations'>): string {
  if (!reason) return t('reasons.none')
  const known = new Set([
    'plugin_installation_version_incompatible', 'control_api_incompatible', 'manifest_unverified',
    'catalog_sequence_invalid', 'publisher_proof_invalid', 'configuration_schema_unverified',
    'scope_approval_required', 'execution_mode_invalid', 'upgrade_apply_failed',
  ])
  return known.has(reason) ? t(`reasons.${reason}`) : t('reasons.other')
}

function compatibilityText(installation: PluginInstallation, t: TFunction<'pluginInstallations'>): string {
  if (installation.stable_reason_code === 'plugin_installation_version_incompatible' ||
    installation.stable_reason_code === 'control_api_incompatible') return t('compatibility.incompatible')
  if (installation.status === 'pending_confirmation' || installation.status === 'installing') {
    return t('compatibility.pending')
  }
  return t('compatibility.verified')
}

// upgradeTarget is what the upgrade dialog approves: the newer version the platform already authorized, applied to
// the installed row (same authorization and revision).
function upgradeTarget(installation: PluginInstallation): PluginInstallation {
  const upgrade = installation.available_upgrade
  if (!upgrade) return installation
  return { ...installation, verification_id: upgrade.verification_id, version: upgrade.version,
    manifest_scopes: upgrade.manifest_scopes, approved_scopes: upgrade.approved_scopes,
    sensitive_scopes: upgrade.sensitive_scopes, new_scopes: upgrade.new_scopes }
}

function canUpgrade(installation: PluginInstallation): boolean {
  return installation.status !== 'uninstalled' &&
    (Boolean(installation.available_upgrade) || installation.status === 'upgrade_failed_lkg_preserved')
}

// A purchased market plugin the platform has not confirmed: this controller's administrator confirms it.
function awaitingController(installation: PluginInstallation): boolean {
  return installation.status === 'pending_confirmation' && installation.authorization_status === 'pending_confirmation'
}

// The platform stopped the authorization: a locally running plugin it disabled, or a pause it owns (operator,
// market delisting/advisory). Only this controller's own pause (paused_by=installation) can be resumed here.
function platformPaused(installation: PluginInstallation): boolean {
  if (installation.authorization_status !== 'disabled') return false
  return installation.status === 'enabled' || (installation.status === 'disabled' &&
    (installation.paused_by === 'operator' || installation.paused_by === 'service'))
}

// A local pause whose owner the server has not told us yet (the license snapshot or paused_by is missing,
// e.g. a write response without the optional fields): neither a platform pause nor resumable until read back.
function pauseOwnerUnknown(installation: PluginInstallation): boolean {
  return installation.status === 'disabled' && installation.paused_by === undefined
}

function canResume(installation: PluginInstallation): boolean {
  return installation.status === 'disabled' && installation.authorization_status === 'disabled' &&
    installation.paused_by === 'installation'
}

function pauseText(installation: PluginInstallation, t: TFunction<'pluginInstallations'>): string | null {
  if (installation.status !== 'disabled' && !platformPaused(installation)) return null
  if (pauseOwnerUnknown(installation)) return t('pause.checking')
  const reason = installation.paused_reason ?? t('pause.noReason')
  if (installation.paused_by === 'installation') {
    return installation.paused_reason ? t('pause.ownReason', { reason }) : t('pause.own')
  }
  if (installation.paused_by === 'operator' || installation.paused_by === 'service') return t(`pause.${installation.paused_by}`, { reason })
  return t('pause.unknown')
}

type InstallationsApi = typeof pluginInstallationsApi

// 我的插件的三个处理阶段（报告 A 菜单裁决）：每组对应服务端一个状态筛选，“全部”不带筛选。
type PlatformGroup = 'all' | 'pending' | 'installed' | 'failed'
const platformGroups: { key: PlatformGroup; status?: PluginInstallationStatus }[] = [
  { key: 'all' }, { key: 'pending', status: 'pending_confirmation' }, { key: 'installed', status: 'enabled' },
  { key: 'failed', status: 'upgrade_failed_lkg_preserved' },
]

// A platform plugin (theme or rule data pack) is used from its own page once installed here.
function installedPlatformPlugin(installation: PluginInstallation): boolean {
  return installation.resource_scope === 'platform' && installation.status === 'enabled'
}

function actionResult(
  api: InstallationsApi, attempt: ActionAttempt, accessToken: string,
): Promise<PluginInstallationMutationResult> {
  const item = attempt.installation
  switch (attempt.kind) {
    case 'confirm':
      return api.confirm(accessToken, item.tenant_scope_id, item.authorization_id, item.revision, attempt.approval!, attempt.key)
    case 'upgrade':
      return api.upgrade(accessToken, item.tenant_scope_id, item.authorization_id, item.revision, attempt.approval!, attempt.key)
    case 'disable':
      return api.disable(accessToken, item.tenant_scope_id, item.authorization_id, item.revision, { reason: attempt.reason! }, attempt.key)
    case 'resume':
      return api.resume(accessToken, item.tenant_scope_id, item.authorization_id, item.revision, attempt.key)
    case 'uninstall':
      return api.uninstall(accessToken, item.tenant_scope_id, item.authorization_id, item.revision, { reason: attempt.reason! }, attempt.key)
  }
}

export default function PluginMarketPage() {
  const { t } = useTranslation('pluginInstallations')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canRead = Boolean(principal && (principal.permissions.includes('plugin_installations.read') || principal.permissions.includes('platform.admin')))
  if (!accessToken || !principal || !sessionEpoch || principal.scope_kind !== 'tenant' ||
    !uuidPattern.test(principal.scope_id) || !principal.tenant_id || !canRead) {
    return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  const key = ownerKey(principal, sessionEpoch)
  // 用户端独立页放进白底卡；平台面板嵌在插件商店的标签页里（已有白底），不再套卡。
  return <PageSection><PluginMarketContent key={key} accessToken={accessToken} principal={principal} owner={key} /></PageSection>
}

/**
 * 我的插件（主控管理员）：本主控的实例级插件（用户控制台主题、规则数据包）。待确认、已安装、失败集中在
 * 这里，详情里确认安装；主题装好后去主题管理启用。只用精确的 plugin_installations.platform.* 权限。
 */
export function PlatformPluginsPanel() {
  const { t } = useTranslation('pluginInstallations')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal || !sessionEpoch || principal.scope_kind !== 'platform' ||
    !principal.permissions.includes('plugin_installations.platform.read')) {
    return <Result status="warning" icon={<ShieldOff size={56} aria-hidden="true" />} title={t('platform.forbiddenTitle')} subTitle={t('platform.forbiddenDescription')} />
  }
  const key = `${ownerKey(principal, sessionEpoch)}:platform`
  return <PluginMarketContent key={key} accessToken={accessToken} principal={principal} owner={key} platform />
}

function PluginMarketContent({ accessToken, principal, owner, platform = false }: {
  accessToken: string; principal: Principal; owner: string; platform?: boolean
}) {
  const { t, i18n } = useTranslation('pluginInstallations')
  const queryClient = useQueryClient()
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const api: InstallationsApi = platform ? platformPluginInstallationsApi : pluginInstallationsApi
  const canManage = platform ? principal.permissions.includes('plugin_installations.platform.manage')
    : principal.permissions.includes('plugin_installations.manage') || principal.permissions.includes('platform.admin')
  const scopeID = principal.scope_id
  const [pluginDraft, setPluginDraft] = useState('')
  const [pluginFilter, setPluginFilter] = useState('')
  const [statusDraft, setStatusDraft] = useState<PluginInstallationStatus | undefined>()
  const [statusFilter, setStatusFilter] = useState<PluginInstallationStatus | undefined>()
  const [cursorState, setCursorState] = useState<CursorState>({ key: '', cursors: [] })
  const cursors = cursorState.key === `${pluginFilter}:${statusFilter ?? ''}` ? cursorState.cursors : []
  const cursor = cursors.at(-1)
  const [selected, setSelected] = useState<PluginInstallation | null>(null)
  const [action, setAction] = useState<ActionSelection | null>(null)
  const [approvedScopes, setApprovedScopes] = useState<string[]>([])
  const [sensitiveConfirmed, setSensitiveConfirmed] = useState(false)
  const [newConfirmed, setNewConfirmed] = useState(false)
  const [reason, setReason] = useState('')
  const [pendingAttempt, setPendingAttempt] = useState<ActionAttempt | null>(null)
  const [lastOutcome, setLastOutcome] = useState<ActionOutcome | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const advisories = useAdvisories(accessToken, true)
  const { t: tStore } = useTranslation('pluginStore')
  const pendingAdvisories = advisories.items.filter((a) => !a.acknowledgement)

  const listQuery = useQuery({
    queryKey: ['plugin-installations', owner, scopeID, pluginFilter, statusFilter, cursor],
    queryFn: () => api.list(accessTokenRef.current, scopeID, {
      limit: 50, ...(cursor ? { cursor } : {}), ...(pluginFilter ? { plugin_id: pluginFilter } : {}),
      ...(statusFilter ? { status: statusFilter } : {}),
    }),
  })
  // 名称按本页插件 ID 向市场批量取（含已下架）；租户会话或读不到时回退为 plugin_id。
  const catalog = usePluginCatalog(accessToken, [...(listQuery.data?.items ?? []).map((item) => item.plugin_id),
    ...(selected ? [selected.plugin_id] : []), ...(pendingAttempt ? [pendingAttempt.installation.plugin_id] : [])])
  const nameOf = (pluginID: string) => pluginName(catalog, pluginID, i18n.resolvedLanguage)
  const detailQuery = useQuery({
    queryKey: ['plugin-installation', owner, scopeID, selected?.authorization_id],
    queryFn: () => api.get(accessTokenRef.current, scopeID, selected!.authorization_id),
    enabled: Boolean(selected),
  })

  const mutation = useMutation({
    gcTime: 0,
    mutationFn: async (attempt: ActionAttempt) => {
      const token = currentTokenForManage(attempt.ownerKey, platform)
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      return actionResult(api, attempt, token)
    },
    onSuccess: (result, attempt) => {
      const authorizationID = attempt.installation.authorization_id
      // Only this attempt is settled: another plugin's pending recovery stays as it is.
      setPendingAttempt((current) => (current && sameAttempt(current, attempt) ? null : current))
      setAction((current) => (current?.installation.authorization_id === authorizationID ? null : current))
      setActionError(null)
      setLastOutcome({ kind: attempt.kind, installation: result.installation })
      // Keep the drawer on whatever the administrator is reading now; open it on the result only when closed.
      setSelected((current) => (!current || current.authorization_id === authorizationID ? result.installation : current))
      void queryClient.invalidateQueries({ queryKey: ['plugin-installations', owner, scopeID] })
      // A write answer may omit the optional license fields (authorization_status/paused_by): show it at once,
      // then read the same object back so the owner of a pause comes from the server, not from this click.
      const detailKey = ['plugin-installation', owner, scopeID, authorizationID]
      queryClient.setQueryData(detailKey, result.installation)
      void queryClient.invalidateQueries({ queryKey: detailKey, exact: true })
    },
    onError: (error, attempt) => {
      setActionError(errorText(error, t))
      // The platform paused it meanwhile: show the current owner and reason instead of a stale resume button.
      if (error instanceof ApiError && error.code === 'plugin_installation_platform_paused') {
        void queryClient.invalidateQueries({ queryKey: ['plugin-installation', owner, scopeID] })
        void queryClient.invalidateQueries({ queryKey: ['plugin-installations', owner, scopeID] })
      }
      if (unknownOutcome(error)) {
        setPendingAttempt(attempt)
        setAction(null)
        return
      }
      // A retry of the pending attempt refused for good (4xx) settles it; a refused signed answer (502) does
      // not tell whether the original request committed, so its recovery entry stays.
      if (error instanceof ApiError && error.status >= 400 && error.status < 500 && error.status !== 408) {
        setPendingAttempt((current) => (current && sameAttempt(current, attempt) ? null : current))
      }
    },
  })

  const items = listQuery.data?.items ?? []
  const nextCursor = listQuery.data?.next_cursor
  const detail = detailQuery.data ?? selected
  const failedLKG = items.find((item) => item.status === 'upgrade_failed_lkg_preserved' && item.lkg_version)
  const listForbidden = listQuery.error instanceof ApiError && listQuery.error.status === 403
  // One unresolved write at a time: until it is retried to a result or abandoned, no other confirm, upgrade,
  // pause, resume or uninstall starts (reading the list and details is unaffected).
  const writeLocked = Boolean(pendingAttempt) || mutation.isPending
  const pendingNote = pendingAttempt ? t('unknown.blocking', {
    plugin: nameOf(pendingAttempt.installation.plugin_id), action: t(`operation.actions.${pendingAttempt.kind}`),
  }) : null

  function openAction(kind: ActionKind, selectedInstallation: PluginInstallation) {
    if (writeLocked) return
    const installation = kind === 'upgrade' ? upgradeTarget(selectedInstallation) : selectedInstallation
    setAction({ kind, installation })
    setApprovedScopes(installation.manifest_scopes)
    setSensitiveConfirmed(false)
    setNewConfirmed(false)
    setReason('')
    setActionError(null)
  }

  function submitAction() {
    if (!action || pendingAttempt) return
    const approval = action.kind === 'confirm' || action.kind === 'upgrade' ? {
      verification_id: action.installation.verification_id,
      approved_scopes: approvedScopes,
      sensitive_permissions_confirmed: sensitiveConfirmed,
      new_permissions_confirmed: newConfirmed,
    } : undefined
    mutation.mutate({
      ...action, ownerKey: owner, key: newPluginInstallationIdempotencyKey(action.kind),
      ...(approval ? { approval } : { reason: reason.trim() }),
    })
  }

  // Resume needs no consent and no reason: it restores exactly what this tenant paused, so it runs directly.
  function resumeNow(installation: PluginInstallation) {
    if (writeLocked) return
    setActionError(null)
    mutation.mutate({ kind: 'resume', installation, ownerKey: owner, key: newPluginInstallationIdempotencyKey('resume') })
  }

  function clearFilters() {
    setPluginDraft('')
    setPluginFilter('')
    setStatusDraft(undefined)
    setStatusFilter(undefined)
    setCursorState({ key: ':', cursors: [] })
  }

  // Three empty states: nothing obtained yet, an empty stage group (e.g. no failures), or a search with no match.
  function emptyState() {
    if (pluginFilter) {
      return <Empty description={<strong>{t('empty.noMatch')}</strong>}>
        <Button onClick={clearFilters}>{t('actions.clearFilters')}</Button>
      </Empty>
    }
    if (statusFilter) {
      const group = platform ? platformGroups.find((item) => item.status === statusFilter)?.key : undefined
      return <Empty description={<strong>{group ? t(`empty.group.${group}`) : t('empty.status', { status: t(`states.${statusFilter}`) })}</strong>} />
    }
    return <Empty description={<><strong>{t(platform ? 'platform.emptyTitle' : 'empty.title')}</strong><div>{t(platform ? 'platform.emptyDescription' : 'empty.description')}</div></>} />
  }

  function applyFilters() {
    const normalized = pluginDraft.trim().toLowerCase()
    setPluginFilter(normalized)
    setStatusFilter(statusDraft)
    setCursorState({ key: `${normalized}:${statusDraft ?? ''}`, cursors: [] })
  }

  const columns = useMemo<TableColumnsType<PluginInstallation>>(() => [
    { title: t('columns.plugin'), dataIndex: 'plugin_id', width: 220, ellipsis: true, render: (value: string) => <Space size={4} wrap>
      <Badge dot={advisories.pending.has(value)} offset={[4, 0]}><Space direction="vertical" size={0}><strong>{pluginName(catalog, value, i18n.resolvedLanguage)}</strong>
        {pluginName(catalog, value, i18n.resolvedLanguage) !== value ? <span className="plugin-market-id">{value}</span> : null}</Space></Badge>
    </Space> },
    { title: t('columns.version'), dataIndex: 'version', width: 110 },
    { title: t('columns.status'), dataIndex: 'status', width: 190, render: (value: PluginInstallationStatus, item) => <Space size={4} wrap>
      <Tag color={statusColor(value)}>{t(`states.${value}`)}</Tag>
      {platformPaused(item) ? <Tag color="orange">{t('states.platformPaused')}</Tag> : null}
      {awaitingController(item) ? <Tag color="gold">{t('states.awaitingController')}</Tag> : null}
      {item.available_upgrade && value !== 'uninstalled' ? <Tag color="blue">{t('states.upgradeAvailable', { version: item.available_upgrade.version })}</Tag> : null}
    </Space> },
    { title: t('columns.scopes'), dataIndex: 'manifest_scopes', width: 100, render: (value: string[]) => value.length },
    { title: t('columns.lkg'), dataIndex: 'lkg_version', width: 130, render: (value: string | null) => value ?? t('lkg.none') },
    { title: t('columns.updated'), dataIndex: 'updated_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value },
    { title: t('columns.actions'), key: 'actions', fixed: 'right', width: 230, render: (_, item) => <Space size={4}>
      <Button size="small" aria-label={t('actions.view')} icon={<Eye size={14} />} onClick={() => setSelected(item)} />
      {canManage && item.status === 'pending_confirmation' ? <Button size="small" type="primary" disabled={writeLocked} onClick={() => openAction('confirm', item)}>{t('actions.confirm')}</Button> : null}
      {canManage && canUpgrade(item) ? <Button size="small" disabled={writeLocked} onClick={() => openAction('upgrade', item)}>{t('actions.upgrade')}</Button> : null}
    </Space> },
  ], [advisories.pending, canManage, catalog, i18n.resolvedLanguage, t, writeLocked])

  const approvalAction = action?.kind === 'confirm' || action?.kind === 'upgrade'
  const sensitiveRequired = Boolean(action?.installation.sensitive_scopes.length)
  const newRequired = Boolean(action?.installation.new_scopes.length)
  const approvalDisabled = approvalAction && ((!sensitiveConfirmed && sensitiveRequired) || (!newConfirmed && newRequired))
  const reasonDisabled = Boolean(action && (action.kind === 'disable' || action.kind === 'uninstall') &&
    ([...reason.trim()].length < 1 || [...reason.trim()].length > 500))

  return <div className="plugin-market-page">
    {platform ? <p className="plugin-market-subtitle">{t('platform.subtitle')}</p> : <>
      <h1>{t('title')}</h1>
      <p className="plugin-market-subtitle">{t('subtitle')}</p>
    </>}
    {platform ? <Segmented<PlatformGroup> className="plugin-market-groups" role="radiogroup" aria-label={t('platform.groups.label')}
      value={platformGroups.find((group) => group.status === statusFilter)?.key ?? 'all'}
      onChange={(key) => {
        const status = platformGroups.find((group) => group.key === key)?.status
        setStatusDraft(status)
        setStatusFilter(status)
        setCursorState({ key: `${pluginFilter}:${status ?? ''}`, cursors: [] })
      }}
      options={platformGroups.map((group) => ({ value: group.key, label: t(`platform.groups.${group.key}`) }))} /> : null}
    <div className="plugin-market-toolbar">
      <Input value={pluginDraft} maxLength={128} placeholder={t('filters.pluginPlaceholder')} onChange={(event) => setPluginDraft(event.target.value)} onPressEnter={applyFilters} />
      {platform ? null : <Select<PluginInstallationStatus> allowClear value={statusDraft} placeholder={t('filters.all')} style={{ minWidth: 180 }} onChange={setStatusDraft} options={Array.from([
        'pending_confirmation', 'authorized', 'installing', 'enabled', 'disabled', 'upgrade_failed_lkg_preserved', 'uninstalled',
      ] as PluginInstallationStatus[]).map((value) => ({ value, label: t(`states.${value}`) }))} />}
      <Button type="primary" icon={<Search size={15} />} onClick={applyFilters}>{t('actions.search')}</Button>
      <Button icon={<RefreshCw size={15} />} loading={listQuery.isFetching} onClick={() => void listQuery.refetch()}>{t('actions.refresh')}</Button>
    </div>
    {/* 恢复结果不确定：插件可能已恢复，原请求重试会回放同一次恢复；不引导重新购买或卸载。 */}
    {pendingAttempt ? <OutcomeUnknown title={t(pendingAttempt.kind === 'resume' ? 'unknown.resumeTitle' : 'unknown.title')}
      detail={t(pendingAttempt.kind === 'resume' ? 'unknown.resumeDescription' : 'unknown.description')} action={<Space wrap>
      <Button size="small" loading={mutation.isPending} onClick={() => mutation.mutate(pendingAttempt)}>{t(pendingAttempt.kind === 'resume' ? 'actions.retryResume' : 'actions.retrySame')}</Button>
      <Button size="small" onClick={() => { setPendingAttempt(null); setActionError(null); void listQuery.refetch() }}>{t('actions.refreshAbandon')}</Button>
    </Space>} /> : actionError ? <FeedbackWhen title={actionError} /> : null}
    {pendingNote ? <p className="plugin-market-pending-note" role="note">{pendingNote}</p> : null}
    {lastOutcome ? <Alert type="success" showIcon closable onClose={() => setLastOutcome(null)}
      message={t('operation.confirmed', {
        action: t(`operation.actions.${lastOutcome.kind}`), status: t(`states.${lastOutcome.installation.status}`),
        revision: lastOutcome.installation.revision,
      })} /> : null}
    {failedLKG ? <FeedbackWhen type="warning" title={t('lkg.preserved', { version: failedLKG.lkg_version })} /> : null}
    {advisories.items.length ? <Collapse size="small" defaultActiveKey={pendingAdvisories.length ? ['advisories'] : []} items={[{
      key: 'advisories',
      label: <Space size={6}><Badge status={pendingAdvisories.length ? 'error' : 'success'} />{pendingAdvisories.length
        ? tStore('advisories.banner', { count: pendingAdvisories.length }) : tStore('tabs.advisories')}</Space>,
      children: <AdvisoryList items={advisories.items} canAcknowledge={canManage} />,
    }]} /> : null}
    {listQuery.isLoading ? <div className="plugin-market-loading" role="status" aria-label={t('accessibility.loading')} aria-live="polite"><Spin /></div> :
      listQuery.isError ? <Result status="error" title={t(listForbidden ? 'forbidden.title' : 'errors.load')} subTitle={listForbidden ? t('forbidden.description') : errorText(listQuery.error, t)} extra={<Button onClick={() => void listQuery.refetch()}>{t('actions.retry')}</Button>} /> :
        items.length === 0 ? emptyState() :
          <Table<PluginInstallation> rowKey="authorization_id" size="small" columns={columns} dataSource={items} pagination={false} scroll={{ x: 1120 }} />}
    {listQuery.isError ? null : <div className="plugin-market-pagination" aria-label={t('pagination.label')}>
      <Button icon={<ChevronLeft size={14} />} disabled={cursors.length === 0 || listQuery.isFetching} onClick={() => setCursorState({ key: `${pluginFilter}:${statusFilter ?? ''}`, cursors: cursors.slice(0, -1) })}>{t('pagination.previous')}</Button>
      <span>{t('pagination.page', { page: cursors.length + 1 })}</span>
      <Button icon={<ChevronRight size={14} />} disabled={!nextCursor || cursors.includes(nextCursor) || listQuery.isFetching} onClick={() => nextCursor && setCursorState({ key: `${pluginFilter}:${statusFilter ?? ''}`, cursors: [...cursors, nextCursor] })}>{t('pagination.next')}</Button>
    </div>}

    <Drawer className="plugin-market-drawer" width="min(760px, 100vw)" title={detail ? nameOf(detail.plugin_id) : t('detail.title')} open={Boolean(selected)} closable onClose={() => setSelected(null)}>
      {detailQuery.isLoading ? <div className="plugin-market-loading"><Spin aria-label={t('accessibility.loading')} /></div> : null}
      {detailQuery.isError ? <Alert type="error" showIcon message={t('errors.detail')} description={errorText(detailQuery.error, t)} /> : null}
      {detail ? <>
        {/* 平台插件：先给下一步（确认安装 / 去对应页面启用），技术字段放在后面。 */}
        {platform && detail.status === 'pending_confirmation' && canManage ? <Alert className="plugin-market-consent-note" type="info" showIcon
          message={t('platform.pendingHint')} action={<Button type="primary" disabled={writeLocked} onClick={() => openAction('confirm', detail)}>{t('actions.confirm')}</Button>} /> : null}
        {installedPlatformPlugin(detail) ? <Alert className="plugin-market-consent-note" type="success" showIcon
          message={t('platform.installed')} description={detail.entrypoint_type === 'theme'
            ? null
            : <Link to="/site/rule-packs">{t('platform.goRulePacks')}</Link>} /> : null}
        <section className="plugin-market-state" aria-label={t('pause.title')}>
          <Space size={4} wrap>
            <Tag color={statusColor(detail.status)}>{t(`states.${detail.status}`)}</Tag>
            {platformPaused(detail) ? <Tag color="orange">{t('states.platformPaused')}</Tag> : null}
            {awaitingController(detail) ? <Tag color="gold">{t('states.awaitingController')}</Tag> : null}
          </Space>
          {pauseOwnerUnknown(detail) ? <p className="plugin-market-state-reason">{t(detailQuery.isError ? 'pause.readFailed' : 'pause.checking')}</p>
            : pauseText(detail, t) ? <p className="plugin-market-state-reason">{pauseText(detail, t)}</p> : null}
          {pendingNote ? <p className="plugin-market-pending-note">{pendingNote}</p> : null}
          {canManage && detail.status !== 'uninstalled' ? <div className="plugin-market-actions"><Space wrap>
            {detail.status === 'pending_confirmation' && !platform ? <Button type="primary" disabled={writeLocked} onClick={() => openAction('confirm', detail)}>{t('actions.confirm')}</Button> : null}
            {canResume(detail) ? <Button type="primary" disabled={Boolean(pendingAttempt)} loading={mutation.isPending && mutation.variables?.kind === 'resume'} onClick={() => resumeNow(detail)}>{t('actions.resume')}</Button> : null}
            {canUpgrade(detail) ? <Button disabled={writeLocked} onClick={() => openAction('upgrade', detail)}>{t('actions.upgrade')}</Button> : null}
            {detail.status === 'enabled' ? <Button disabled={writeLocked} onClick={() => openAction('disable', detail)}>{t('actions.disable')}</Button> : null}
            {pauseOwnerUnknown(detail) ? <Button icon={<RefreshCw size={14} />} loading={detailQuery.isFetching} onClick={() => void detailQuery.refetch()}>{t('actions.refreshState')}</Button> : null}
          </Space></div> : null}
        </section>
        {/* What an administrator reads first: name, version, compatibility, reason and fallback. Internal IDs and
            digests are for support and go under 诊断信息. */}
        <Descriptions bordered size="small" column={1} className="plugin-market-summary">
          <Descriptions.Item label={t('detail.plugin')}>{detail.plugin_id}</Descriptions.Item>
          <Descriptions.Item label={t('detail.version')}>{detail.version}</Descriptions.Item>
          <Descriptions.Item label={t('detail.compatibility')}>{compatibilityText(detail, t)}</Descriptions.Item>
          <Descriptions.Item label={t('detail.reason')}>{stableReasonText(detail.stable_reason_code, t)}</Descriptions.Item>
          <Descriptions.Item label={t('detail.lkg')}>{detail.lkg_version ?? t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.approved')}>{detail.approved_scopes.length
            ? <Space size={[8, 4]} wrap>{detail.approved_scopes.map((scope) => <ScopeLabel key={scope} scope={scope} t={t} />)}</Space> : t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.updated')}>{formatDateTime(detail.updated_at, i18n.resolvedLanguage ?? 'zh-CN') || detail.updated_at}</Descriptions.Item>
        </Descriptions>
        <Collapse size="small" ghost className="plugin-market-diagnostics" items={[{
          key: 'diagnostics', label: t('detail.diagnostics'),
          children: <Descriptions bordered size="small" column={1}>
            <Descriptions.Item label={t('detail.revision')}>{detail.revision}</Descriptions.Item>
            <Descriptions.Item label={t('detail.generation')}>{detail.identity_generation}</Descriptions.Item>
            <Descriptions.Item label={t('detail.installation')}>{detail.installation_id}</Descriptions.Item>
            <Descriptions.Item label={t('detail.verification')}>{detail.verification_id}</Descriptions.Item>
            <Descriptions.Item label={t('detail.manifestDigest')}><code className="plugin-market-digest">{detail.manifest_sha256}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.schemaDigest')}><code className="plugin-market-digest">{detail.configuration_schema_sha256}</code></Descriptions.Item>
            <Descriptions.Item label={t('detail.scopes')}>{detail.manifest_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
            <Descriptions.Item label={t('detail.sensitive')}>{detail.sensitive_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
            <Descriptions.Item label={t('detail.added')}>{detail.new_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
          </Descriptions>,
        }]} />
        {/* 主题与规则包不加页面、不调签名接口；页面声明与签名公钥只对租户扩展有意义。 */}
        {platform ? null : <>
          <UIPageDisclosure token={accessToken} pluginID={detail.plugin_id} version={detail.version} manifestSHA256={detail.manifest_sha256} />
          <SigningKeyPanel token={accessToken} />
          <PluginIdentityKeyPanel token={accessToken} principal={principal} installation={detail} />
        </>}
        {canManage && detail.status !== 'uninstalled' ? <div className="plugin-market-danger">
          <Button danger disabled={writeLocked} onClick={() => openAction('uninstall', detail)}>{t('actions.uninstall')}</Button>
        </div> : null}
      </> : null}
    </Drawer>

    <Modal open={Boolean(action)} title={action?.kind === 'confirm' ? t('consent.installTitle') : action?.kind === 'upgrade' ? t('consent.upgradeTitle') : action?.kind === 'disable' ? t('protective.disableTitle') : t('protective.uninstallTitle')}
      onCancel={() => !mutation.isPending && setAction(null)} maskClosable={!mutation.isPending} keyboard={!mutation.isPending} closable={!mutation.isPending}
      okText={action?.kind === 'confirm' ? t('actions.confirmInstall') : action?.kind === 'upgrade' ? t('actions.confirmUpgrade') : action?.kind === 'disable' ? t('actions.confirmDisable') : t('actions.confirmUninstall')}
      cancelText={t('actions.cancel')} confirmLoading={mutation.isPending} okButtonProps={{ danger: action?.kind === 'disable' || action?.kind === 'uninstall', disabled: Boolean(approvalDisabled || reasonDisabled) }} onOk={submitAction}>
      {approvalAction && action ? <>
        <Alert className="plugin-market-consent-note" type="info" showIcon message={t('consent.exact')} />
        <Checkbox.Group value={approvedScopes} onChange={(values) => setApprovedScopes(values as string[])}>
          <Space direction="vertical">{action.installation.manifest_scopes.map((scope) => <Checkbox key={scope} value={scope}><ScopeLabel scope={scope} t={t} /></Checkbox>)}</Space>
        </Checkbox.Group>
        {sensitiveRequired ? <div><Checkbox checked={sensitiveConfirmed} onChange={(event) => setSensitiveConfirmed(event.target.checked)}>{t('consent.sensitive')}</Checkbox><div>{t('consent.sensitiveHelp')}</div></div> : null}
        {/* A first installation has no earlier consent: it confirms what this install needs; only an upgrade adds permissions. */}
        {newRequired ? <div><Checkbox checked={newConfirmed} onChange={(event) => setNewConfirmed(event.target.checked)}>
          {t(action.kind === 'upgrade' ? 'consent.added' : 'consent.firstInstall')}</Checkbox>
          <div>{t(action.kind === 'upgrade' ? 'consent.addedHelp' : 'consent.firstInstallHelp')}</div></div> : null}
        {platform ? null : <UIPageDisclosure token={accessToken} pluginID={action.installation.plugin_id} version={action.installation.version}
          manifestSHA256={action.kind === 'upgrade' ? undefined : action.installation.manifest_sha256} />}
      </> : action ? <label>{t('protective.reason')}<Input.TextArea aria-label={t('protective.reason')} value={reason} maxLength={500} placeholder={t('protective.reasonPlaceholder')} onChange={(event) => setReason(event.target.value)} /></label> : null}
    </Modal>
  </div>
}
