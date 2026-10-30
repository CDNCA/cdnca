import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Descriptions, Modal, Select, Space, Tag } from 'antd'
import { RefreshCw, UploadCloud } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import { createControlUpgradeRequestMetadata } from '../api/controlUpgrades'
import {
  nativeControlUpgradesApi, previewNativeUpgradeBundle, type NativeUpgradeAttempt,
  type NativeUpgradeOption, type NativeUpgradeOptions, type NativeUpgradePreview, type NativeUpgradePublication,
} from '../api/controlUpgrades.native'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { issueRefusalMessage, maintenanceUpgradeMessage, maintenanceUpgradeReasonMessage, upgradeTargetReasonMessage } from '../i18n/maintenanceUpgrade'
import { FeedbackWhen, OutcomeUnknown, useFeedback } from '@cdnca/ui'

type Session = ReturnType<typeof useSessionStore.getState>
type MessageKey = Parameters<typeof maintenanceUpgradeMessage>[1]
const canManage = (session: Session) => session.status === 'authenticated' && session.principal?.scope_kind === 'platform' &&
  session.principal.tenant_id === null && Boolean(session.accessToken) &&
  session.principal.permissions.some((permission) => ['control.upgrades.manage', 'platform.admin'].includes(permission))
const sessionOwner = (session: Session) => JSON.stringify([session.sessionEpoch, session.status, session.principal?.scope_kind,
  session.principal?.scope_id, session.principal?.tenant_id, session.principal?.user_id, [...session.principal?.permissions ?? []].sort()])
const unknownWrite = (error: unknown) => !(error instanceof ApiError) || error.code === 'network_error' ||
  error.code === 'invalid_response' || [0, 408, 429].includes(error.status) || error.status >= 500

// "inline" renders only the upgrade action, its alerts and confirmation dialog;
// publication facts are read from the master upgrade log instead.
export default function ControlUpgradesNative({ actionsTarget, variant = 'panel' }: { actionsTarget?: HTMLElement | null; variant?: 'panel' | 'inline' }) {
  const session = useSessionStore()
  const owner = sessionOwner(session)
  return <NativeUpgradePanel key={owner} owner={owner} permitted={canManage(session)} actionsTarget={actionsTarget} inline={variant === 'inline'} />
}

function NativeUpgradePanel({ owner, permitted, actionsTarget, inline }: { owner: string; permitted: boolean; actionsTarget?: HTMLElement | null; inline: boolean }) {
  const { i18n } = useTranslation()
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const mt = (key: MessageKey) => maintenanceUpgradeMessage(locale, key)
  const queryClient = useQueryClient()
  const feedback = useFeedback()
  const mounted = useRef(true)
  const fileInput = useRef<HTMLInputElement>(null)
  const uploadSequence = useRef(0)
  const pendingRef = useRef(false)
  const [open, setOpen] = useState(false)
  // fallback: true 表示 /issue 返回 503，降级到手工上传路径
  const [fallback, setFallback] = useState(false)
  const [draft, setDraft] = useState<{ rawJSON: string; preview: NativeUpgradePreview; revision: number } | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const [reading, setReading] = useState(false)
  const [pending, setPending] = useState(false)
  const [unknown, setUnknown] = useState<NativeUpgradeAttempt | null>(null)
  const [errorKey, setErrorKey] = useState<MessageKey | null>(null)
  const [published, setPublished] = useState<NativeUpgradePublication | null>(null)
  const [now, setNow] = useState(Date.now())
  // '' = channel latest (or the provider's pin); otherwise the chosen artifact_id.
  const [chosen, setChosen] = useState('')
  const current = () => mounted.current && canManage(useSessionStore.getState()) && sessionOwner(useSessionStore.getState()) === owner
  const query = useQuery({
    queryKey: ['native-control-upgrade-status', owner],
    queryFn: () => nativeControlUpgradesApi.status(useSessionStore.getState().accessToken!),
    enabled: permitted, retry: false, gcTime: 0, staleTime: 0,
    refetchInterval: (status) => status.state.error instanceof ApiError && status.state.error.status === 404 ? false : 5000,
  })
  const optionsQuery = useQuery({
    queryKey: ['native-control-upgrade-options', owner],
    queryFn: () => nativeControlUpgradesApi.options(useSessionStore.getState().accessToken!),
    enabled: permitted && open && !fallback, retry: false, gcTime: 0, staleTime: 0,
  })
  const versionOptions = optionsQuery.data?.options ?? null
  // Publishing needs the version list: a failed read is an error, never the
  // channel latest in its place.
  const versionsReady = Boolean(versionOptions) && !optionsQuery.isError
  const chosenOption = versionOptions?.items.find((item) => item.artifact_id === chosen && item.selectable)
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; uploadSequence.current += 1 }
  }, [])
  useEffect(() => {
    if (!permitted) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [permitted])
  const fresh = (at = Date.now()) => Boolean(query.data && !query.isError &&
    at - query.dataUpdatedAt < 15000 && at - Date.parse(query.data.observed_at) < 30000 &&
    Date.parse(query.data.observed_at) - at < 5000)
  const facts = fresh(now) ? query.data : undefined
  const ready = Boolean(facts?.runtime.ready && facts.runtime.reason === 'ready')
  const revisionMatches = Boolean(draft && facts && draft.revision === facts.publication_revision)
  const canSubmit = permitted && ready && revisionMatches && confirmed && !pending && !reading && !unknown
  const publication = published && (!facts?.publication || published.publication_revision > facts.publication.publication_revision)
    ? published : facts?.publication
  const execution = publication && facts?.publication?.receipt_id === publication.receipt_id ? facts.execution : undefined
  const runnerReceipt = execution?.receipt
  const executionKey: MessageKey = runnerReceipt ? ({ applied: 'nativeApplied', rolled_back: 'nativeRolledBack', failed: 'nativeFailed' } as const)[runnerReceipt.result]
    : execution?.state === 'running' ? 'nativeRunning' : execution?.state === 'not_started' ? 'nativeNotStarted' : 'nativeExecutionUnknown'
  const phaseKeys: Record<string, MessageKey> = {
    verified: 'nativePhaseVerified', expanded: 'nativePhaseExpanded', preflighted: 'nativePhasePreflighted',
    drained: 'nativePhaseDrained', control_stopped: 'nativePhaseControlStopped', database_backed_up: 'nativePhaseDatabaseBackedUp',
    database_migrated: 'nativePhaseDatabaseMigrated', activated: 'nativePhaseActivated', healthy: 'nativePhaseHealthy',
    contracted: 'nativePhaseContracted', completed: 'nativePhaseCompleted', rolling_back: 'nativePhaseRollingBack',
    rolled_back: 'nativePhaseRolledBack', failed: 'nativePhaseFailed',
  }

  const readFile = async (file?: File) => {
    if (!file || !current() || pendingRef.current || unknown || !ready || !facts) return
    const sequence = ++uploadSequence.current
    const revision = facts.publication_revision
    setDraft(null); setConfirmed(false); setErrorKey(null); setReading(true)
    try {
      if (file.size > 256 * 1024) throw new Error('oversized')
      const rawJSON = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer())
      const preview = previewNativeUpgradeBundle(rawJSON)
      if (current() && sequence === uploadSequence.current) setDraft({ rawJSON, preview, revision })
    } catch {
      if (current() && sequence === uploadSequence.current) {
        setErrorKey('nativeInvalidFile')
        if (fileInput.current) fileInput.current.value = ''
      }
    } finally {
      if (current() && sequence === uploadSequence.current) setReading(false)
    }
  }

  const publish = async (attempt: NativeUpgradeAttempt) => {
    if (!current() || pendingRef.current) return
    pendingRef.current = true
    setPending(true); setErrorKey(null)
    try {
      const receipt = await nativeControlUpgradesApi.publish(useSessionStore.getState().accessToken!, attempt)
      if (!current()) return
      setPublished(receipt); setUnknown(null); setDraft(null); setConfirmed(false); setOpen(false); setFallback(false)
      if (fileInput.current) fileInput.current.value = ''
      void query.refetch()
      void queryClient.invalidateQueries({ queryKey: ['maintenance-upgrade-status'] })
    } catch (error) {
      if (!current()) return
      if (fileInput.current) fileInput.current.value = ''
      if (unknownWrite(error)) {
        setUnknown(attempt); setOpen(false); setDraft(null); setConfirmed(false)
      } else {
        setUnknown(null); setDraft(null); setConfirmed(false)
        setErrorKey(error instanceof ApiError && error.status === 403 ? 'nativePermissionDenied' :
          error instanceof ApiError && error.status === 401 ? 'nativeSessionExpired' :
            error instanceof ApiError && ['version_conflict', 'idempotency_conflict', 'control_upgrade_plan_conflict'].includes(error.code ?? '') ? 'nativeRevisionConflict' :
              error instanceof ApiError && ['invalid_control_upgrade_plan', 'invalid_request'].includes(error.code ?? '') ? 'nativePlanRejected' : 'nativePublishFailed')
      }
      void query.refetch()
    } finally {
      pendingRef.current = false
      if (current()) setPending(false)
    }
  }

  const issueAndPublish = async () => {
    if (!current() || pendingRef.current || !fresh()) return
    pendingRef.current = true
    setPending(true); setErrorKey(null)
    try {
      const metadata = createControlUpgradeRequestMetadata('native')
      const receipt = await nativeControlUpgradesApi.issue(useSessionStore.getState().accessToken!, metadata.idempotencyKey,
        chosenOption?.artifact_id)
      if (!current()) return
      setPublished(receipt); setConfirmed(false); setOpen(false); setFallback(false)
      void query.refetch()
      void queryClient.invalidateQueries({ queryKey: ['maintenance-upgrade-status'] })
    } catch (error) {
      if (!current()) return
      if (error instanceof ApiError && error.status === 503 && error.code === 'plan_source_unavailable') {
        // 授权端不可用，静默降级到手工上传路径
        setFallback(true)
        setConfirmed(false)
      } else if (unknownWrite(error)) {
        setOpen(false); setConfirmed(false)
      } else {
        setConfirmed(false)
        const blocked = error instanceof ApiError && error.code === 'upgrade_target_blocked'
        // The refreshed list shows why the version cannot be granted now.
        if (blocked) { setChosen(''); void optionsQuery.refetch() }
        // 授权端业务拒绝（409，upgrade_target_blocked 或透传的授权端 code）：弹窗说明具体原因。
        // 主控自身的发布冲突码不属于授权端拒绝。
        const refused = error instanceof ApiError && error.status === 409 &&
          !['version_conflict', 'idempotency_conflict', 'control_upgrade_plan_conflict'].includes(error.code)
        if (refused) {
          feedback.error(mt('nativeIssueRefusedTitle'),
            `${issueRefusalMessage(locale, error.code, error.reasonCode)} (${error.reasonCode ?? error.code})`)
        }
        setErrorKey(error instanceof ApiError && error.status === 403 ? 'nativePermissionDenied' :
          error instanceof ApiError && error.status === 401 ? 'nativeSessionExpired' : refused ? 'nativeVersionBlocked' : 'nativePublishFailed')
      }
    } finally {
      pendingRef.current = false
      if (current()) setPending(false)
    }
  }

  if (!permitted) return <Button disabled title={mt('nativePermissionDenied')} icon={<UploadCloud size={14} />}>{mt('upgradeControl')}</Button>
  const idleActionsTarget = actionsTarget && facts?.runtime.ready && facts.runtime.reason === 'ready' &&
    facts.execution.state === 'not_started' && !facts.execution.phase && !facts.execution.receipt &&
    !publication && !published && !unknown && !errorKey && !pending && !open && !reading && !draft ? actionsTarget : null
  const upgradeButton = <Button icon={<UploadCloud size={14} />} disabled={!ready || pending || Boolean(unknown)} onClick={() => {
        if (!current() || !fresh()) return
        if (fileInput.current) fileInput.current.value = ''
        setOpen(true); setDraft(null); setFallback(false); setConfirmed(false); setErrorKey(null); setChosen(''); void query.refetch()
      }}>{mt('upgradeControl')}</Button>
  const actions = inline ? upgradeButton : <Space wrap>
      {upgradeButton}
      <Button icon={<RefreshCw size={14} />} loading={query.isFetching} onClick={() => void query.refetch()}>{mt('nativeRefresh')}</Button>
    </Space>

  const targetVersion = facts?.publication?.target_version ?? undefined
  const currentVersion = facts?.publication?.current_version ?? undefined

  return <div className={`native-upgrade-panel${idleActionsTarget ? ' native-upgrade-panel--idle' : ''}${inline ? ' native-upgrade-panel--inline' : ''}`}>
    {idleActionsTarget ? createPortal(actions, idleActionsTarget) : actions}
    {query.isError ? <FeedbackWhen title={mt(query.error instanceof ApiError && query.error.status === 403 ? 'nativePermissionDenied' : 'nativeStatusFailed')} /> :
      query.data && !facts ? <FeedbackWhen type="warning" title={mt('nativeStatusStale')} /> : null}
    {facts && !facts.runtime.ready ? <p>{maintenanceUpgradeReasonMessage(locale, facts.runtime.reason === 'execution_unavailable' ? 'control_upgrade_execution_unavailable' : facts.runtime.reason)}</p> : null}
    {published ? <Alert type="info" showIcon message={mt('nativePublished')} /> : null}
    {unknown ? <OutcomeUnknown title={mt('nativeOutcomeUnknown')} action={
      <Button loading={pending} onClick={() => void publish(unknown)}>{mt('nativeRetry')}</Button>
    } /> : null}
    {errorKey && !open ? <Alert type="error" showIcon message={mt(errorKey)} /> : null}
    {publication && !inline ? <Descriptions size="small" column={1} className="native-upgrade-facts" title={mt('nativePublication')} items={[
      { key: 'receipt', label: mt('nativePublicationReceipt'), children: <code>{publication.receipt_id}</code> },
      { key: 'revision', label: mt('nativeRevision'), children: formatNumber(publication.publication_revision, locale) },
      { key: 'plan', label: mt('nativePlanID'), children: <code>{publication.plan_id}</code> },
      { key: 'versions', label: mt('nativeVersionChange'), children: `${publication.current_version} → ${publication.target_version}` },
      { key: 'digest', label: mt('nativeBundleDigest'), children: <code>{publication.bundle_sha256}</code> },
      { key: 'request', label: mt('nativeRequestID'), children: <code>{publication.request_id}</code> },
      { key: 'execution', label: mt('nativeExecution'), children: <Tag color={runnerReceipt?.result === 'applied' ? 'success' : runnerReceipt ? 'error' : undefined}>{mt(executionKey)}</Tag> },
      ...(execution?.phase ? [{ key: 'phase', label: mt('nativePhase'), children: mt(phaseKeys[execution.phase]) }] : []),
      ...(runnerReceipt ? [
        { key: 'runnerReceipt', label: mt('nativeExecutionReceipt'), children: <code>{runnerReceipt.id}</code> },
        { key: 'completed', label: mt('nativeCompletedAt'), children: formatDateTime(new Date(runnerReceipt.completed_at * 1000).toISOString(), locale) },
        ...(runnerReceipt.error_code ? [{ key: 'failure', label: mt('nativeFailure'), children: mt(['target_health_failed', 'health_failed'].includes(runnerReceipt.error_code) ? 'nativeHealthFailed' : 'nativeExecutionFailed') }] : []),
      ] : []),
    ]} /> : null}
    <Modal title={mt('upgradeControl')} open={open} width={680} className="native-upgrade-modal" maskClosable={!pending}
      closable={pending ? false : { 'aria-label': mt('nativeClose') }} onCancel={() => {
        uploadSequence.current += 1
        if (fileInput.current) fileInput.current.value = ''
        setOpen(false); setDraft(null); setFallback(false); setConfirmed(false); setReading(false)
      }}
      footer={fallback ? (
        <Button type="primary" loading={pending} disabled={!canSubmit} onClick={() => {
          if (!current() || !fresh() || !canSubmit || !draft) return
          void publish({ rawJSON: draft.rawJSON, expectedRevision: draft.revision, metadata: createControlUpgradeRequestMetadata('native') })
        }}>{mt('nativePublish')}</Button>
      ) : (
        <Button type="primary" loading={pending} disabled={!ready || pending || !confirmed || !versionsReady} onClick={() => void issueAndPublish()}>
          {mt('nativePublish')}
        </Button>
      )}>
      {fallback ? (
        <>
          <Alert type="warning" showIcon message={mt('nativeFallbackUpload')} />
          <Alert type="info" showIcon message={mt('nativeUploadHint')} />
          <label className="native-upgrade-upload"><span>{mt('nativeUpload')}</span>
            <input ref={fileInput} type="file" accept=".json,application/json" disabled={!ready || pending || reading}
              onChange={(event) => void readFile(event.target.files?.[0])} />
          </label>
          {errorKey ? <Alert type="error" showIcon message={mt(errorKey)} /> : null}
          {draft ? <>
            <Tag color="warning">{mt('nativeUnverified')}</Tag>
            <Descriptions size="small" column={1} className="native-upgrade-facts" items={[
              { key: 'plan', label: mt('nativePlanID'), children: <code>{draft.preview.planID}</code> },
              { key: 'installation', label: mt('nativeInstallationID'), children: <code>{draft.preview.installationID}</code> },
              { key: 'versions', label: mt('nativeVersionChange'), children: `${draft.preview.currentVersion} → ${draft.preview.targetVersion}` },
              { key: 'rollback', label: mt('nativeRollbackVersion'), children: draft.preview.rollbackVersion },
              { key: 'sequence', label: mt('nativeSequence'), children: formatNumber(draft.preview.releaseSequence, locale) },
              { key: 'channel', label: mt('nativeChannelRevision'), children: formatNumber(draft.preview.channelRevision, locale) },
              { key: 'protocol', label: mt('nativeProtocol'), children: formatNumber(draft.preview.protocolVersion, locale) },
              { key: 'digest', label: mt('nativeArtifactDigest'), children: <code>{draft.preview.artifactSHA256}</code> },
            ]} />
            {!revisionMatches ? <Alert type="warning" showIcon message={mt('nativeRevisionConflict')} /> : null}
            <Checkbox checked={confirmed} disabled={pending} onChange={(event) => setConfirmed(event.target.checked)}>{mt('nativeMaintenanceConfirm')}</Checkbox>
          </> : null}
        </>
      ) : (
        <>
          <Alert type="info" showIcon message={mt('nativeAutoUpgradeHint')} />
          {currentVersion ? <p>{mt('nativeVersionChange')}: {currentVersion}{targetVersion ? ` → ${targetVersion}` : ''}</p> : null}
          <VersionPicker locale={locale} loading={optionsQuery.isFetching} failed={optionsQuery.isError}
            data={optionsQuery.data} chosen={chosen} disabled={pending} onChange={(value) => { setChosen(value); setConfirmed(false) }} />
          {errorKey ? <Alert type="error" showIcon message={mt(errorKey)} /> : null}
          <Checkbox checked={confirmed} disabled={pending} onChange={(event) => setConfirmed(event.target.checked)}>{mt('nativeMaintenanceConfirm')}</Checkbox>
        </>
      )}
    </Modal>
  </div>
}

function VersionPicker({ locale, loading, failed, data, chosen, disabled, onChange }: {
  locale: string; loading: boolean; failed: boolean; data?: NativeUpgradeOptions; chosen: string; disabled: boolean
  onChange: (value: string) => void
}) {
  const mt = (key: MessageKey) => maintenanceUpgradeMessage(locale, key)
  if (failed) return <FeedbackWhen type="warning" title={mt('nativeVersionListFailed')} />
  const options = data?.options
  const locked = options?.target_mode === 'pinned'
  const selected = options?.items.find((item) => item.artifact_id === chosen)
  const tags = (item: NativeUpgradeOption) => <>
    {item.operation === 'rollback' ? <Tag color="warning">{mt('nativeVersionDowngradeTag')}</Tag> : null}
    {item.operation === 'reinstall' ? <Tag>{mt('nativeVersionCurrentTag')}</Tag> : null}
    {item.channel_target ? <Tag color="processing">{mt('nativeVersionTargetTag')}</Tag> : null}
    {item.pinned ? <Tag color="blue">{mt('nativeVersionLocked')}</Tag> : null}
  </>
  return <div className="native-upgrade-version-picker">
    <label htmlFor="native-upgrade-version">{mt('nativeVersionPick')}</label>
    <Select id="native-upgrade-version" aria-label={mt('nativeVersionPick')} loading={loading} disabled={disabled || !options}
      value={chosen} onChange={onChange} style={{ width: '100%' }} optionLabelProp="title"
      options={[
        { value: '', title: locked ? mt('nativeVersionLocked') : mt('nativeVersionLatest'),
          label: locked ? mt('nativeVersionLocked') : mt('nativeVersionLatest') },
        ...(options?.items ?? []).map((item) => ({
          value: item.artifact_id, disabled: !item.selectable, title: item.version,
          label: <span className="native-upgrade-version-option" data-version={item.version}>
            <span>{item.version}</span>{tags(item)}
            {item.selectable ? null : <small>{upgradeTargetReasonMessage(locale, item.reason)}</small>}
          </span>,
        })),
      ]} />
    {options?.items.some((item) => item.operation === 'rollback') ? <p className="native-upgrade-version-note">{mt('nativeVersionDowngradeNote')}</p> : null}
    {selected ? <Descriptions size="small" column={1} className="native-upgrade-facts" items={[
      { key: 'version', label: mt('nativeConfirmVersion'), children: <>{selected.version} {tags(selected)}</> },
      ...(selected.control_schema_head ? [{ key: 'schema', label: mt('nativeVersionSchema'),
        children: `${options?.current_schema_head ?? '?'} → ${selected.control_schema_head}` }] : []),
      ...(selected.published_at ? [{ key: 'published', label: mt('nativePublishedAt'),
        children: formatDateTime(new Date(selected.published_at * 1000).toISOString(), locale) }] : []),
      { key: 'notes', label: mt('nativeVersionNotes'),
        children: selected.release_notes ? <span className="native-upgrade-release-notes">{selected.release_notes}</span> : mt('nativeVersionNoNotes') },
    ]} /> : null}
  </div>
}
