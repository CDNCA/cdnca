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
import '../../i18n/pluginInstallations'

import { AdvisoryList } from './AdvisoryList'
import { SigningKeyPanel, UIPageDisclosure } from './PluginUIDisclosure'
import { useAdvisories } from './useAdvisories'

import './PluginMarketPage.css'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

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
    case 'invalid_response': return t('errors.invalidResponse')
    default: return localizedUnknownApiError(error, t('errors.request'))
  }
}

function unknownOutcome(error: unknown): boolean {
  if (!(error instanceof ApiError)) return true
  return error.code === 'plugin_installation_result_unknown' || error.status === 0 || error.status === 408 || error.status >= 500
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
// market delisting/advisory, or no recorded owner). Only this controller's own pause (paused_by=installation)
// can be resumed here.
function platformPaused(installation: PluginInstallation): boolean {
  if (installation.authorization_status !== 'disabled') return false
  return installation.status === 'enabled' || (installation.status === 'disabled' && installation.paused_by !== 'installation')
}

function canResume(installation: PluginInstallation): boolean {
  return installation.status === 'disabled' && installation.authorization_status === 'disabled' &&
    installation.paused_by === 'installation'
}

function pauseText(installation: PluginInstallation, t: TFunction<'pluginInstallations'>): string | null {
  if (installation.status !== 'disabled' && !platformPaused(installation)) return null
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
  return <PluginMarketContent key={key} accessToken={accessToken} principal={principal} owner={key} />
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
      setPendingAttempt(null)
      setAction(null)
      setActionError(null)
      setLastOutcome({ kind: attempt.kind, installation: result.installation })
      setSelected(result.installation)
      void queryClient.invalidateQueries({ queryKey: ['plugin-installations', owner, scopeID] })
      queryClient.setQueryData(['plugin-installation', owner, scopeID, result.installation.authorization_id], result.installation)
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
      }
    },
  })

  const items = listQuery.data?.items ?? []
  const nextCursor = listQuery.data?.next_cursor
  const detail = detailQuery.data ?? selected
  const failedLKG = items.find((item) => item.status === 'upgrade_failed_lkg_preserved' && item.lkg_version)
  const listForbidden = listQuery.error instanceof ApiError && listQuery.error.status === 403

  function openAction(kind: ActionKind, selectedInstallation: PluginInstallation) {
    const installation = kind === 'upgrade' ? upgradeTarget(selectedInstallation) : selectedInstallation
    setAction({ kind, installation })
    setApprovedScopes(installation.manifest_scopes)
    setSensitiveConfirmed(false)
    setNewConfirmed(false)
    setReason('')
    setActionError(null)
  }

  function submitAction() {
    if (!action) return
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
    setActionError(null)
    mutation.mutate({ kind: 'resume', installation, ownerKey: owner, key: newPluginInstallationIdempotencyKey('resume') })
  }

  function applyFilters() {
    const normalized = pluginDraft.trim().toLowerCase()
    setPluginFilter(normalized)
    setStatusFilter(statusDraft)
    setCursorState({ key: `${normalized}:${statusDraft ?? ''}`, cursors: [] })
  }

  const columns = useMemo<TableColumnsType<PluginInstallation>>(() => [
    { title: t('columns.plugin'), dataIndex: 'plugin_id', width: 220, ellipsis: true, render: (value: string) => <Space size={4} wrap>
      <Badge dot={advisories.pending.has(value)} offset={[4, 0]}><span>{value}</span></Badge>
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
      {canManage && item.status === 'pending_confirmation' ? <Button size="small" type="primary" onClick={() => openAction('confirm', item)}>{t('actions.confirm')}</Button> : null}
      {canManage && canUpgrade(item) ? <Button size="small" onClick={() => openAction('upgrade', item)}>{t('actions.upgrade')}</Button> : null}
    </Space> },
  ], [advisories.pending, canManage, i18n.resolvedLanguage, t])

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
        items.length === 0 ? <Empty description={<><strong>{t(platform ? 'platform.emptyTitle' : 'empty.title')}</strong><div>{t(platform ? 'platform.emptyDescription' : 'empty.description')}</div></>} /> :
          <Table<PluginInstallation> rowKey="authorization_id" size="small" columns={columns} dataSource={items} pagination={false} scroll={{ x: 1120 }} />}
    {listQuery.isError ? null : <div className="plugin-market-pagination" aria-label={t('pagination.label')}>
      <Button icon={<ChevronLeft size={14} />} disabled={cursors.length === 0 || listQuery.isFetching} onClick={() => setCursorState({ key: `${pluginFilter}:${statusFilter ?? ''}`, cursors: cursors.slice(0, -1) })}>{t('pagination.previous')}</Button>
      <span>{t('pagination.page', { page: cursors.length + 1 })}</span>
      <Button icon={<ChevronRight size={14} />} disabled={!nextCursor || cursors.includes(nextCursor) || listQuery.isFetching} onClick={() => nextCursor && setCursorState({ key: `${pluginFilter}:${statusFilter ?? ''}`, cursors: [...cursors, nextCursor] })}>{t('pagination.next')}</Button>
    </div>}

    <Drawer className="plugin-market-drawer" width="min(760px, 100vw)" title={detail?.plugin_id ?? t('detail.title')} open={Boolean(selected)} closable onClose={() => setSelected(null)}>
      {detailQuery.isLoading ? <div className="plugin-market-loading"><Spin aria-label={t('accessibility.loading')} /></div> : null}
      {detailQuery.isError ? <Alert type="error" showIcon message={t('errors.detail')} description={errorText(detailQuery.error, t)} /> : null}
      {detail ? <>
        {/* 平台插件：先给下一步（确认安装 / 去对应页面启用），技术字段放在后面。 */}
        {platform && detail.status === 'pending_confirmation' && canManage ? <Alert className="plugin-market-consent-note" type="info" showIcon
          message={t('platform.pendingHint')} action={<Button type="primary" onClick={() => openAction('confirm', detail)}>{t('actions.confirm')}</Button>} /> : null}
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
          {pauseText(detail, t) ? <p className="plugin-market-state-reason">{pauseText(detail, t)}</p> : null}
          {canManage && detail.status !== 'uninstalled' ? <div className="plugin-market-actions"><Space wrap>
            {detail.status === 'pending_confirmation' && !platform ? <Button type="primary" onClick={() => openAction('confirm', detail)}>{t('actions.confirm')}</Button> : null}
            {canResume(detail) ? <Button type="primary" loading={mutation.isPending && mutation.variables?.kind === 'resume'} onClick={() => resumeNow(detail)}>{t('actions.resume')}</Button> : null}
            {canUpgrade(detail) ? <Button onClick={() => openAction('upgrade', detail)}>{t('actions.upgrade')}</Button> : null}
            {detail.status === 'enabled' ? <Button onClick={() => openAction('disable', detail)}>{t('actions.disable')}</Button> : null}
          </Space></div> : null}
        </section>
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
          <Descriptions.Item label={t('detail.plugin')}>{detail.plugin_id}</Descriptions.Item>
          <Descriptions.Item label={t('detail.version')}>{detail.version}</Descriptions.Item>
          <Descriptions.Item label={t('detail.revision')}>{detail.revision}</Descriptions.Item>
          <Descriptions.Item label={t('detail.installation')} span={2}>{detail.installation_id}</Descriptions.Item>
          <Descriptions.Item label={t('detail.verification')} span={2}>{detail.verification_id}</Descriptions.Item>
          <Descriptions.Item label={t('detail.compatibility')} span={2}>{compatibilityText(detail, t)}</Descriptions.Item>
          <Descriptions.Item label={t('detail.manifestDigest')} span={2}><code className="plugin-market-digest">{detail.manifest_sha256}</code></Descriptions.Item>
          <Descriptions.Item label={t('detail.schemaDigest')} span={2}><code className="plugin-market-digest">{detail.configuration_schema_sha256}</code></Descriptions.Item>
          <Descriptions.Item label={t('detail.scopes')} span={2}>{detail.manifest_scopes.join(', ')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.approved')} span={2}>{detail.approved_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.sensitive')} span={2}>{detail.sensitive_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.added')} span={2}>{detail.new_scopes.join(', ') || t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.generation')}>{detail.identity_generation}</Descriptions.Item>
          <Descriptions.Item label={t('detail.lkg')}>{detail.lkg_version ?? t('lkg.none')}</Descriptions.Item>
          <Descriptions.Item label={t('detail.reason')}>{stableReasonText(detail.stable_reason_code, t)}</Descriptions.Item>
          <Descriptions.Item label={t('detail.updated')}>{formatDateTime(detail.updated_at, i18n.resolvedLanguage ?? 'zh-CN') || detail.updated_at}</Descriptions.Item>
        </Descriptions>
        {/* 主题与规则包不加页面、不调签名接口；页面声明与签名公钥只对租户扩展有意义。 */}
        {platform ? null : <>
          <UIPageDisclosure token={accessToken} pluginID={detail.plugin_id} version={detail.version} manifestSHA256={detail.manifest_sha256} />
          <SigningKeyPanel token={accessToken} />
        </>}
        {canManage && detail.status !== 'uninstalled' ? <div className="plugin-market-danger">
          <Button danger onClick={() => openAction('uninstall', detail)}>{t('actions.uninstall')}</Button>
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
          <Space direction="vertical">{action.installation.manifest_scopes.map((scope) => <Checkbox key={scope} value={scope}><code>{scope}</code></Checkbox>)}</Space>
        </Checkbox.Group>
        {sensitiveRequired ? <div><Checkbox checked={sensitiveConfirmed} onChange={(event) => setSensitiveConfirmed(event.target.checked)}>{t('consent.sensitive')}</Checkbox><div>{t('consent.sensitiveHelp')}</div></div> : null}
        {newRequired ? <div><Checkbox checked={newConfirmed} onChange={(event) => setNewConfirmed(event.target.checked)}>{t('consent.added')}</Checkbox><div>{t('consent.addedHelp')}</div></div> : null}
        {platform ? null : <UIPageDisclosure token={accessToken} pluginID={action.installation.plugin_id} version={action.installation.version}
          manifestSHA256={action.kind === 'upgrade' ? undefined : action.installation.manifest_sha256} />}
      </> : action ? <label>{t('protective.reason')}<Input.TextArea aria-label={t('protective.reason')} value={reason} maxLength={500} placeholder={t('protective.reasonPlaceholder')} onChange={(event) => setReason(event.target.value)} /></label> : null}
    </Modal>
  </div>
}
