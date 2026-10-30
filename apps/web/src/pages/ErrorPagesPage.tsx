import { useEffect, useMemo, useState } from 'react'
import {
  Alert,
  Button,
  Input,
  Modal,
  Popconfirm,
  Radio,
  Result,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
} from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import type { TableColumnsType } from 'antd'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  errorPageScopeOverrideSlotKeys,
  errorPagesApi,
  type ErrorPageSlotBinding,
  type ErrorPageSlotPublication,
  type ErrorPageSlotKey,
  type ErrorPageScopeOverride,
  type ErrorPageScopeOverrideBindingInput,
  type ErrorPageScopeOverrideSlotKey,
  type ErrorPageScopeOverrideTargetInput,
} from '../api/errorPages'
import { nodesApi } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import '../i18n/errorPagesPage'
import './ErrorPagesPage.css'

type Owner = readonly ['platform', string, string, number]
type ScopeKind = 'node' | 'region'
type OverrideDraft = {
  scopeKind: ScopeKind
  target: string
  items: ErrorPageScopeOverrideSlotKey[]
  contents: Partial<Record<ErrorPageScopeOverrideSlotKey, string>>
}
type OverrideEditor = { kind: 'create' } | { kind: 'edit'; item: ErrorPageScopeOverride }
type AssetAttempt = {
  key: ErrorPageScopeOverrideSlotKey
  content: string
  sha256: string
  sizeBytes: number
  initiateKey: string
  uploadKey: string
  finalizeKey: string
}
type SaveAttempt = {
  editor: OverrideEditor
  target: ErrorPageScopeOverrideTargetInput
  assets: AssetAttempt[]
  writeKey: string
}
type DeleteAttempt = { item: ErrorPageScopeOverride; writeKey: string }

const legacyErrorPageOptions = ['p456', 'p400', 'p403', 'waf_block', 'p502', 'p504', 'p513', 'p512', 'p514', 'host_not_found', 'access_ip_not_allow', 'p515'] as const
type LegacyErrorPageOption = typeof legacyErrorPageOptions[number]
const legacySlotByOption: Record<LegacyErrorPageOption, ErrorPageSlotKey> = {
  p456: 'blacklist', p400: 'http_400', p403: 'http_403', waf_block: 'waf_block', p502: 'http_502', p504: 'http_504',
  p513: 'traffic_exceeded', p512: 'package_expired', p514: 'site_locked', host_not_found: 'domain_unconfigured',
  access_ip_not_allow: 'node_ip_access', p515: 'connection_limit',
}
// The pages a node answers itself (errpage-3 slot node pages): the alert
// words what the node returns while unsaved instead of the theme delivery.
const ownFallbackSlots: Partial<Record<ErrorPageSlotKey, true>> = {
  blacklist: true, http_403: true, traffic_exceeded: true, package_expired: true, node_ip_access: true, connection_limit: true,
}
const positiveDisplayID = /^[1-9][0-9]{0,18}$/
const staleRead = new Error('error page owner changed during request')
const emptyDraft: OverrideDraft = { scopeKind: 'node', target: '', items: [], contents: {} }

function ownerFor(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  return ['platform', principal.scope_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'platform' && (principal.permissions.includes('error_pages.read') || principal.permissions.includes('platform.admin'))
}

function canManage(principal: Principal): boolean {
  return principal.scope_kind === 'platform' && (principal.permissions.includes('error_pages.manage') || principal.permissions.includes('platform.admin'))
}

function currentAccess(ownerKey: string, manage = false): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal) || manage && !canManage(principal)) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function operationKey(kind: string): string {
  return `error-page-${kind}-${crypto.randomUUID()}`
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.code === 'unsafe_content') return 'errors.unsafeContent'
  if (error.code === 'scan_rejected') return 'errors.scanRejected'
  if (error.code === 'quota_exceeded') return 'errors.quotaExceeded'
  if (error.status === 403 || error.code === 'permission_denied') return 'errors.forbiddenTitle'
  if (error.status === 404) return 'errors.notFound'
  if (error.status === 409) return 'errors.conflict'
  if (error.status === 412) return 'errors.stale'
  if (error.status === 422 || error.status === 400) return 'errors.validation'
  if (error.status === 503) return 'errors.unavailable'
  if (error.code === 'invalid_response') return 'errors.invalidResponse'
  if (error.code === 'network_error') return 'errors.network'
  return 'errors.requestFailed'
}

function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied')
}

function isUnknownWrite(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 0 || error.code === 'network_error')
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

type GlobalSaveAttempt = {
  slotKey: ErrorPageSlotKey
  revision: number
  content: string
  sha256: string
  sizeBytes: number
  initiateKey: string
  uploadKey: string
  finalizeKey: string
  bindKey: string
}

function GlobalErrorPagePanel({ owner, ownerKey, manageable }: { owner: Owner; ownerKey: string; manageable: boolean }) {
  const { t } = useTranslation('errorPagesPage')
  const [messageApi, messageContext] = useFeedbackMessage()
  const client = useQueryClient()
  const [selected, setSelected] = useState<LegacyErrorPageOption>('p456')
  const [draftContent, setDraftContent] = useState('')
  const [saveError, setSaveError] = useState<string>()
  const [pendingSave, setPendingSave] = useState<GlobalSaveAttempt>()
  const [preview, setPreview] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [published, setPublished] = useState<ErrorPageSlotPublication | null>()
  const token = currentAccess(ownerKey)
  const slotKey = legacySlotByOption[selected]
  const slotsQueryKey = ['error-pages', ...owner, 'global-slots'] as const
  const slotQueryKey = ['error-pages', ...owner, 'global-slot', slotKey] as const
  const slots = useQuery({
    queryKey: slotsQueryKey,
    enabled: Boolean(token),
    queryFn: async () => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      const result = await errorPagesApi.listSlots(accessToken)
      if (!currentAccess(ownerKey)) throw staleRead
      return result
    },
    retry: false,
  })
  const slot = useQuery({
    queryKey: slotQueryKey,
    enabled: Boolean(token && slots.isSuccess),
    queryFn: async () => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      const result = await errorPagesApi.getSlot(accessToken, slotKey)
      if (!currentAccess(ownerKey)) throw staleRead
      return result
    },
    retry: false,
  })

  useEffect(() => {
    setDraftContent('')
    setSaveError(undefined)
    setPendingSave(undefined)
    setPublished(undefined)
  }, [slotKey])

  useEffect(() => {
    if (slot.data) setDraftContent(slot.data.content)
  }, [slot.data])

  const binding: ErrorPageSlotBinding | undefined = slot.data?.binding ?? slots.data?.items.find((item) => item.key === slotKey)
  const buildSaveAttempt = async (): Promise<GlobalSaveAttempt | null> => {
    const blob = new Blob([draftContent], { type: 'text/html' })
    if (blob.size < 1 || blob.size > 1048576) return null
    return {
      slotKey,
      revision: binding?.revision ?? 0,
      content: draftContent,
      sha256: await sha256(draftContent),
      sizeBytes: blob.size,
      initiateKey: operationKey(`${slotKey}-initiate`),
      uploadKey: operationKey(`${slotKey}-upload`),
      finalizeKey: operationKey(`${slotKey}-finalize`),
      bindKey: operationKey(`${slotKey}-bind`),
    }
  }

  const executeSave = async (attempt: GlobalSaveAttempt) => {
    setSaveError(undefined)
    try {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      const initiated = await errorPagesApi.initiateAsset(accessToken, owner[1], 'text/html', attempt.sizeBytes, attempt.sha256, attempt.initiateKey)
      await errorPagesApi.uploadAssetContent(accessToken, initiated.value.id, new Blob([attempt.content], { type: 'text/html' }), 'text/html', attempt.uploadKey)
      const finalized = await errorPagesApi.finalizeAsset(accessToken, initiated.value.id, attempt.finalizeKey)
      const bound = await errorPagesApi.bindSlot(accessToken, attempt.slotKey, finalized.value.id, attempt.revision, attempt.bindKey)
      setPendingSave(undefined)
      setPublished(bound.value.publication ?? null)
      await Promise.all([
        client.invalidateQueries({ queryKey: slotsQueryKey }),
        client.invalidateQueries({ queryKey: slotQueryKey }),
      ])
      void messageApi.success(t(bound.value.publication ? 'legacy.notices.savedPublishing' : 'legacy.notices.saved'))
    } catch (error) {
      if (isUnknownWrite(error)) setPendingSave(attempt)
      setSaveError(errorKey(error))
    }
  }

  // Restore the system default: unbind the slot (the theme's page is back).
  const restore = async () => {
    if (!binding?.asset_id) return
    setSaveError(undefined)
    setRestoring(true)
    try {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      const unbound = await errorPagesApi.unbindSlot(accessToken, slotKey, binding.revision, operationKey(`${slotKey}-unbind`))
      setPublished(unbound.value.publication ?? null)
      await Promise.all([
        client.invalidateQueries({ queryKey: slotsQueryKey }),
        client.invalidateQueries({ queryKey: slotQueryKey }),
      ])
      void messageApi.success(t(unbound.value.publication ? 'legacy.notices.restoredPublishing' : 'legacy.notices.restored'))
    } catch (error) {
      setSaveError(errorKey(error))
    } finally {
      setRestoring(false)
    }
  }

  const save = async () => {
    const attempt = pendingSave ?? await buildSaveAttempt()
    if (!attempt) {
      setSaveError('legacy.validation.required')
      return
    }
    await executeSave(attempt)
  }

  return <div className="error-page-global-panel" data-testid="error-page-global-panel">
    {messageContext}
    <div className="error-page-global-row">
      <span className="error-page-global-label">{t('legacy.selectorLabel')}</span>
      <Radio.Group
        className="error-page-selector"
        optionType="button"
        buttonStyle="outline"
        value={selected}
        onChange={(event) => setSelected(event.target.value as LegacyErrorPageOption)}
        aria-label={t('legacy.selectorLabel')}
      >
        {legacyErrorPageOptions.map((key) => <Radio.Button key={key} value={key}>{t(`legacy.options.${key}`)}</Radio.Button>)}
      </Radio.Group>
    </div>
    {slots.isError ? <FeedbackWhen title={t(errorKey(slots.error))} action={<Button size="small" onClick={() => void slots.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {slot.isError ? <FeedbackWhen title={t(errorKey(slot.error))} action={<Button size="small" onClick={() => void slot.refetch()}>{t('actions.retry')}</Button>} /> : null}
    <div className="error-page-global-row error-page-global-content-row">
      <span className="error-page-global-label">{t('legacy.contentLabel')}</span>
      <div className="error-page-global-editor">
        {slot.data ? <Alert
          className="error-page-global-alert"
          type={slot.data.delivery === 'none' ? 'warning' : 'info'}
          showIcon
          message={slotKey === 'site_locked' ? t('legacy.siteLocked')
            : slotKey in ownFallbackSlots ? t(`legacy.ownFallback.${slotKey}`)
              : t(`legacy.delivery.${slot.data.delivery}`)}
          description={t('legacy.variables')}
        /> : null}
        <Input.TextArea
          rows={12}
          value={draftContent}
          onChange={(event) => setDraftContent(event.target.value)}
          disabled={!manageable || slots.isLoading || slot.isLoading || slot.isError}
          aria-label={t('legacy.contentLabel')}
        />
        <div className="error-page-global-editor-footer">
          <span className="error-page-global-status" data-testid="error-page-global-status">
            {binding?.asset_id ? t('legacy.configured', { revision: binding.revision }) : slot.data ? t('legacy.builtin') : null}
          </span>
          <Space>
            <Button onClick={() => setPreview(true)} disabled={!draftContent}>{t('legacy.actions.preview')}</Button>
            {manageable && binding?.asset_id ? <Popconfirm title={t('legacy.actions.restoreConfirm')} okText={t('regional.actions.confirm')} cancelText={t('actions.cancel')} onConfirm={() => void restore()}>
              <Button loading={restoring}>{t('legacy.actions.restore')}</Button>
            </Popconfirm> : null}
            {manageable ? <Button type="primary" onClick={() => void save()} loading={slot.isLoading || slots.isLoading} disabled={slots.isError || slot.isError}>{t('actions.save')}</Button> : null}
          </Space>
        </div>
        {published ? <Alert className="error-page-global-alert" type="success" showIcon role="status"
          message={t('legacy.publishing', { revision: published.revision, count: published.queued_scopes })}
          action={<Link to="/site/publications">{t('legacy.actions.viewPublications')}</Link>} /> : null}
        {saveError ? (pendingSave ? <OutcomeUnknown className="error-page-global-alert" title={t('legacy.errors.unknown')}
          action={<Space><Button size="small" onClick={() => void save()}>{t('actions.exactRetry')}</Button><Button size="small" onClick={() => { setPendingSave(undefined); setSaveError(undefined); void slot.refetch() }}>{t('actions.abandon')}</Button></Space>} />
          : <FeedbackWhen title={t(saveError)} onClose={() => setSaveError(undefined)} />) : null}
      </div>
    </div>
    <Modal open={preview} title={t('legacy.actions.preview')} width={760} footer={null} onCancel={() => setPreview(false)} destroyOnHidden>
      {/* sandbox without allow-scripts: the page renders but never runs code. */}
      <iframe className="error-page-preview-frame" title={t('legacy.previewTitle')} sandbox="" srcDoc={draftContent} />
    </Modal>
  </div>
}

function RegionalOverridesPanel({ owner, ownerKey, manageable }: { owner: Owner; ownerKey: string; manageable: boolean }) {
  const { t, i18n } = useTranslation('errorPagesPage')
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const client = useQueryClient()
  const [editor, setEditor] = useState<OverrideEditor>()
  const [draft, setDraft] = useState<OverrideDraft>(emptyDraft)
  const [targetSearch, setTargetSearch] = useState('')
  const [editorLoading, setEditorLoading] = useState(false)
  const [saveError, setSaveError] = useState<string>()
  const [pendingSave, setPendingSave] = useState<SaveAttempt>()
  const [pendingDelete, setPendingDelete] = useState<DeleteAttempt>()
  const [selectedRows, setSelectedRows] = useState<React.Key[]>([])
  // Node and region pickers read GET /v1/nodes, which needs nodes.read on top of error_pages.*.
  const canListNodes = useSessionStore((state) => state.principal?.permissions.some((code) => code === 'nodes.read' || code === 'platform.admin') ?? false)
  const token = currentAccess(ownerKey)
  const queryKey = ['error-pages', ...owner, 'scope-overrides'] as const
  const overrides = useQuery({
    queryKey,
    enabled: Boolean(token),
    queryFn: async () => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      const result = await errorPagesApi.listScopeOverrides(accessToken)
      if (!currentAccess(ownerKey)) throw staleRead
      return result
    },
    retry: false,
  })
  const nodeTargets = useQuery({
    queryKey: ['error-pages', ...owner, 'node-targets', draft.scopeKind, targetSearch.trim()],
    enabled: Boolean(canListNodes && editor?.kind === 'create' && draft.scopeKind === 'node' && currentAccess(ownerKey)),
    queryFn: async () => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      return nodesApi.list(accessToken, { limit: 20, search: targetSearch.trim() || undefined })
    },
    retry: false,
  })
  const regionTargets = useQuery({
    queryKey: ['error-pages', ...owner, 'region-targets'],
    enabled: Boolean(canListNodes && editor?.kind === 'create' && draft.scopeKind === 'region' && currentAccess(ownerKey)),
    queryFn: async () => {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      const result = await nodesApi.list(accessToken, { limit: 100 })
      return [...new Set(result.items.map((item) => item.region).filter(Boolean))].sort((left, right) => left.localeCompare(right, i18n.language))
    },
    retry: false,
  })

  const closeEditor = () => {
    setEditor(undefined)
    setDraft(emptyDraft)
    setTargetSearch('')
    setEditorLoading(false)
    setSaveError(undefined)
    setPendingSave(undefined)
  }

  const openCreate = () => {
    setDraft(emptyDraft)
    setTargetSearch('')
    setSaveError(undefined)
    setPendingSave(undefined)
    setEditor({ kind: 'create' })
  }

  const openEdit = async (item: ErrorPageScopeOverride) => {
    setEditor({ kind: 'edit', item })
    setDraft({
      scopeKind: item.target.kind,
      target: item.target.kind === 'node' ? item.target.node_display_id : item.target.region,
      items: item.items.map((entry) => entry.key),
      contents: {},
    })
    setTargetSearch('')
    setSaveError(undefined)
    setPendingSave(undefined)
    setEditorLoading(true)
    try {
      const accessToken = currentAccess(ownerKey)
      if (!accessToken) throw staleRead
      const value = await errorPagesApi.getScopeOverride(accessToken, item.display_id)
      if (!currentAccess(ownerKey)) throw staleRead
      setDraft({
        scopeKind: value.target.kind,
        target: value.target.kind === 'node' ? value.target.node_display_id : value.target.region,
        items: value.items.map((entry) => entry.key),
        contents: Object.fromEntries(value.items.map((entry) => [entry.key, entry.content ?? ''])),
      })
    } catch (error) {
      setSaveError(errorKey(error))
    } finally {
      setEditorLoading(false)
    }
  }

  const buildSaveAttempt = async (): Promise<SaveAttempt | null> => {
    if (!editor || draft.items.length === 0) return null
    const target = draft.scopeKind === 'node'
      ? positiveDisplayID.test(draft.target) ? { kind: 'node', node_display_id: draft.target, region: '' } as const : null
      : draft.target.trim() === draft.target && draft.target.length >= 1 && draft.target.length <= 64
        ? { kind: 'region', node_display_id: '', region: draft.target } as const
        : null
    if (!target) return null
    const assets: AssetAttempt[] = []
    for (const key of errorPageScopeOverrideSlotKeys) {
      if (!draft.items.includes(key)) continue
      const content = draft.contents[key] ?? ''
      const blob = new Blob([content], { type: 'text/html' })
      if (blob.size < 1 || blob.size > 1048576) return null
      assets.push({
        key,
        content,
        sha256: await sha256(content),
        sizeBytes: blob.size,
        initiateKey: operationKey(`${key}-initiate`),
        uploadKey: operationKey(`${key}-upload`),
        finalizeKey: operationKey(`${key}-finalize`),
      })
    }
    return { editor, target, assets, writeKey: operationKey(editor.kind === 'create' ? 'override-create' : 'override-update') }
  }

  const executeSave = async (attempt: SaveAttempt) => {
    setSaveError(undefined)
    try {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      const items: ErrorPageScopeOverrideBindingInput[] = []
      for (const asset of attempt.assets) {
        const blob = new Blob([asset.content], { type: 'text/html' })
        const initiated = await errorPagesApi.initiateAsset(accessToken, owner[1], 'text/html', asset.sizeBytes, asset.sha256, asset.initiateKey)
        await errorPagesApi.uploadAssetContent(accessToken, initiated.value.id, blob, 'text/html', asset.uploadKey)
        const finalized = await errorPagesApi.finalizeAsset(accessToken, initiated.value.id, asset.finalizeKey)
        items.push({ key: asset.key, asset_id: finalized.value.id })
      }
      if (attempt.editor.kind === 'create') {
        await errorPagesApi.createScopeOverride(accessToken, attempt.target, items, attempt.writeKey)
      } else {
        await errorPagesApi.updateScopeOverride(accessToken, attempt.editor.item.display_id, items, attempt.editor.item.revision, attempt.writeKey)
      }
      setPendingSave(undefined)
      closeEditor()
      await client.invalidateQueries({ queryKey })
      void messageApi.success(t('regional.notices.saved'))
    } catch (error) {
      if (isUnknownWrite(error)) setPendingSave(attempt)
      setSaveError(errorKey(error))
    }
  }

  const save = async () => {
    const attempt = pendingSave ?? await buildSaveAttempt()
    if (!attempt) {
      setSaveError('regional.validation.required')
      return
    }
    await executeSave(attempt)
  }

  const executeDelete = async (attempt: DeleteAttempt) => {
    try {
      const accessToken = currentAccess(ownerKey, true)
      if (!accessToken) throw new ApiError('Permission denied', 403, 'permission_denied')
      await errorPagesApi.deleteScopeOverride(accessToken, attempt.item.display_id, attempt.item.revision, attempt.writeKey)
      setPendingDelete(undefined)
      await client.invalidateQueries({ queryKey })
      void messageApi.success(t('regional.notices.deleted'))
    } catch (error) {
      if (isUnknownWrite(error)) setPendingDelete(attempt)
      else void feedback.error(t(errorKey(error)))
    }
  }

  const columns: TableColumnsType<ErrorPageScopeOverride> = [
    {
      title: t('regional.columns.scope'),
      key: 'scope',
      width: 360,
      render: (_, item) => item.target.kind === 'node'
        ? <span>{t('regional.targets.nodeValue', { id: item.target.node_display_id, name: item.target.node_name })}</span>
        : <span>{t('regional.targets.regionValue', { region: item.target.region })}</span>,
    },
    {
      title: t('regional.columns.items'),
      key: 'items',
      width: 360,
      render: (_, item) => item.items.map((entry) => t(`regional.items.${entry.key}`)).join('、'),
    },
    {
      title: t('regional.columns.actions'),
      key: 'actions',
      width: 310,
      render: (_, item) => manageable ? <Space size={10}>
        <Button type="link" size="small" onClick={() => void openEdit(item)}>{t('actions.edit')}</Button>
        <Popconfirm
          title={t('regional.dialogs.deleteConfirm')}
          okText={t('regional.actions.confirm')}
          cancelText={t('actions.cancel')}
          onConfirm={() => void executeDelete({ item, writeKey: operationKey('override-delete') })}
        >
          <Button type="link" size="small" danger>{t('actions.delete')}</Button>
        </Popconfirm>
      </Space> : null,
    },
  ]

  const targetOptions = editor?.kind === 'edit'
    ? [{ value: draft.target, label: draft.scopeKind === 'node'
      ? t('regional.targets.nodeValue', { id: editor.item.target.kind === 'node' ? editor.item.target.node_display_id : '', name: editor.item.target.kind === 'node' ? editor.item.target.node_name : '' })
      : draft.target }]
    : draft.scopeKind === 'node'
      ? nodeTargets.data?.items.map((item) => ({ value: item.display_id, label: `${item.display_id} ${item.name}`, title: item.ipv4 ?? item.ipv6 })) ?? []
      : regionTargets.data?.map((region) => ({ value: region, label: region })) ?? []

  if (isForbidden(overrides.error)) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />

  return <div className="error-page-regional-panel">
    {messageContext}
    <div className="error-page-regional-toolbar">
      {manageable ? <Button type="primary" onClick={openCreate}>{t('regional.actions.add')}</Button> : <span />}
      <span>{t('regional.count', { count: overrides.data?.total ?? 0 })}</span>
    </div>
    {pendingDelete ? <OutcomeUnknown title={t('regional.errors.unknown')} action={<Space><Button size="small" onClick={() => void executeDelete(pendingDelete)}>{t('actions.exactRetry')}</Button><Button size="small" onClick={() => { setPendingDelete(undefined); void overrides.refetch() }}>{t('actions.abandon')}</Button></Space>} className="error-page-regional-alert" /> : null}
    {overrides.isError ? <FeedbackWhen title={t(errorKey(overrides.error))} action={<Button size="small" onClick={() => void overrides.refetch()}>{t('actions.retry')}</Button>} /> : null}
    <Table
      className="error-page-regional-table"
      rowKey="display_id"
      size="small"
      loading={overrides.isLoading}
      dataSource={overrides.data?.items ?? []}
      columns={columns}
      tableLayout="fixed"
      rowSelection={{ selectedRowKeys: selectedRows, onChange: setSelectedRows, columnWidth: 70 }}
      pagination={false}
      locale={{ emptyText: <span className="error-page-table-empty">{t('regional.empty')}</span> }}
    />

    <Modal
      className="error-page-override-modal"
      width={520}
      open={Boolean(editor)}
      title={t(editor?.kind === 'edit' ? 'regional.dialogs.edit' : 'regional.dialogs.add')}
      onCancel={closeEditor}
      destroyOnHidden
      footer={<Space><Button type="primary" loading={editorLoading} onClick={() => void save()}>{t('regional.actions.confirm')}</Button><Button onClick={closeEditor}>{t('actions.cancel')}</Button></Space>}
    >
      <Spin spinning={editorLoading}>
        <div className="error-page-override-form">
          <label>{t('regional.fields.scope')}{t('regional.labelSuffix')}</label>
          <Radio.Group value={draft.scopeKind} disabled={editor?.kind === 'edit'} onChange={(event) => {
            setDraft({ ...emptyDraft, scopeKind: event.target.value as ScopeKind })
            setTargetSearch('')
            setPendingSave(undefined)
            setSaveError(undefined)
          }}>
            <Radio.Button value="node">{t('regional.targets.node')}</Radio.Button>
            <Radio.Button value="region">{t('regional.targets.region')}</Radio.Button>
          </Radio.Group>

          <label>{t(draft.scopeKind === 'node' ? 'regional.fields.node' : 'regional.fields.region')}{t('regional.labelSuffix')}</label>
          <Select
            className="error-page-target-select"
            aria-label={t(draft.scopeKind === 'node' ? 'regional.fields.node' : 'regional.fields.region')}
            showSearch
            filterOption={draft.scopeKind === 'region'}
            value={draft.target || undefined}
            disabled={editor?.kind === 'edit'}
            loading={draft.scopeKind === 'node' ? nodeTargets.isLoading : regionTargets.isLoading}
            placeholder={t(draft.scopeKind === 'node' ? 'regional.placeholders.node' : 'regional.placeholders.region')}
            onSearch={draft.scopeKind === 'node' ? setTargetSearch : undefined}
            onChange={(value) => { setDraft((current) => ({ ...current, target: value })); setPendingSave(undefined) }}
            options={targetOptions}
          />
          {!canListNodes && editor?.kind === 'create' ? <Alert type="warning" showIcon message={t('regional.noNodePermission')} /> : null}

          <label>{t('regional.fields.items')}{t('regional.labelSuffix')}</label>
          <Select
            key={draft.items.join('|') || 'empty'}
            className="error-page-items-select"
            aria-label={t('regional.fields.items')}
            value={undefined}
            placeholder={t('regional.placeholders.items')}
            virtual={false}
            listHeight={284}
            classNames={{ popup: { root: 'error-page-items-popup' } }}
            onChange={(value: ErrorPageScopeOverrideSlotKey) => {
              setDraft((current) => current.items.includes(value)
                ? current
                : { ...current, items: [...current.items, value] })
              setPendingSave(undefined)
              setSaveError(undefined)
            }}
            options={errorPageScopeOverrideSlotKeys
              .filter((key) => !draft.items.includes(key))
              .map((key) => ({ value: key, label: t(`regional.items.${key}`) }))}
          />

          {errorPageScopeOverrideSlotKeys.filter((key) => draft.items.includes(key)).map((key) => <div className="error-page-content-field" key={key}>
            <label>{t(`regional.items.${key}`)}{t('regional.labelSuffix')}</label>
            <div className="error-page-content-control">
              <Input.TextArea
                aria-label={t(`regional.items.${key}`)}
                value={draft.contents[key] ?? ''}
                autoSize={{ minRows: 6, maxRows: 14 }}
                onChange={(event) => {
                  const value = event.target.value
                  setDraft((current) => ({ ...current, contents: { ...current.contents, [key]: value } }))
                  setPendingSave(undefined)
                  setSaveError(undefined)
                }}
              />
              <button
                type="button"
                className="error-page-content-remove"
                aria-label={t('regional.actions.removeItem', { item: t(`regional.items.${key}`) })}
                onClick={() => {
                  setDraft((current) => {
                    const contents = { ...current.contents }
                    delete contents[key]
                    return { ...current, items: current.items.filter((item) => item !== key), contents }
                  })
                  setPendingSave(undefined)
                  setSaveError(undefined)
                }}
              >×</button>
            </div>
          </div>)}
          {saveError ? <Alert
            className="error-page-override-error"
            type={pendingSave ? 'warning' : 'error'}
            showIcon
            message={t(pendingSave ? 'regional.errors.unknown' : saveError)}
            action={pendingSave ? <Space><Button size="small" onClick={() => void save()}>{t('actions.exactRetry')}</Button><Button size="small" onClick={() => { setPendingSave(undefined); setSaveError(undefined); void overrides.refetch() }}>{t('actions.abandon')}</Button></Space> : undefined}
          /> : null}
        </div>
      </Spin>
    </Modal>
  </div>
}

export default function ErrorPagesPage() {
  const { t } = useTranslation('errorPagesPage')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [activeTab, setActiveTab] = useState('global')
  const owner = useMemo(() => principal ? ownerFor(principal, sessionEpoch) : null, [principal, sessionEpoch])

  if (!accessToken || !principal) return null
  if (!owner || !canRead(principal)) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  const ownerKey = JSON.stringify(owner)

  return <section className="identity-page error-pages-page" aria-label={t('heading')}>
    <h1 className="visually-hidden">{t('heading')}</h1>
    <Tabs
      className="error-page-tabs"
      activeKey={activeTab}
      onChange={setActiveTab}
      items={[{ key: 'global', label: t('tabs.global') }, { key: 'regional', label: t('tabs.regional') }]}
    />
    {activeTab === 'global'
      ? <GlobalErrorPagePanel owner={owner} ownerKey={ownerKey} manageable={canManage(principal)} />
      : <RegionalOverridesPanel owner={owner} ownerKey={ownerKey} manageable={canManage(principal)} />}
  </section>
}
