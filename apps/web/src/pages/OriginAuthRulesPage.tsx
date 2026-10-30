import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Button, Checkbox, Descriptions, Drawer, Form, Input, InputNumber, Modal, Popconfirm,
  Result, Select, Space, Table, Tag, Tooltip, Typography,
} from 'antd'
import { useFeedbackMessage } from '@cdnca/ui'
import type { TableColumnsType } from 'antd'
import { ChevronLeft, ChevronRight, Eye, Pencil, Plus, RefreshCw, RotateCw, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  originAuthRulesApi,
  type OriginAuthAlgorithm,
  type OriginAuthProvider,
  type OriginAuthRule,
  type OriginAuthRuleConfig,
} from '../api/originAuthRules'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import '../i18n/originAuthRules'

type Owner = readonly ['tenant', string, string, number]

interface RuleDraft {
  siteID: string
  sourcePosition: number
  provider: OriginAuthProvider
  algorithm: OriginAuthAlgorithm
  endpoint: string
  bucket: string
  pathPrefix: string
  region: string
  service: string
  ttl: number
  credentialID: string
  credentialRevision: number
  enabled: boolean
}

interface PendingWrite {
  run: () => Promise<OriginAuthRule>
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleRead = new ApiError('Session changed', 0, 'stale_session')
const defaultDraft: RuleDraft = {
  siteID: '', sourcePosition: 1, provider: 's3', algorithm: 'aws4-hmac-sha256', endpoint: '',
  bucket: '', pathPrefix: '/', region: '', service: 's3', ttl: 900, credentialID: '',
  credentialRevision: 1, enabled: false,
}

function operationKey() {
  const random = typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`
  return `origin-auth-${random}`
}

export function originAuthRuleOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.scope_id || !principal.tenant_id ||
    !principal.user_id || !sessionEpoch ||
    !uuidPattern.test(principal.scope_id) || !uuidPattern.test(principal.user_id)) return null
  return ['tenant', principal.scope_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal) {
  return principal.permissions.includes('origin_auth.read')
}

function canManage(principal: Principal) {
  return principal.permissions.includes('origin_auth.manage')
}

export function currentOriginAuthRuleAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !canRead(principal)) return null
  const owner = originAuthRuleOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

export function originAuthRuleErrorKey(error: unknown) {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 403 || error.code === 'permission_denied' || error.code === 'origin_auth_permission_denied') return 'errors.forbiddenTitle'
  if (error.status === 404) return 'errors.notFound'
  if (error.status === 409) return 'errors.conflict'
  if (error.status === 412) return 'errors.stale'
  if (error.status === 422 || error.status === 400) return 'errors.validation'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status === 503) return 'errors.unavailable'
  if (error.code === 'network_error') return 'errors.network'
  if (error.code === 'origin_auth_invalid_response' || error.code === 'origin_auth_scope_mismatch') return 'errors.invalidResponse'
  return 'errors.requestFailed'
}

function isForbidden(error: unknown) {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied' || error.code === 'origin_auth_permission_denied')
}

function isUnknownWrite(error: unknown) {
  return error instanceof ApiError && (error.code === 'origin_auth_result_unknown' || error.code === 'network_error')
}

function configFromDraft(draft: RuleDraft): OriginAuthRuleConfig {
  return {
    provider: draft.provider,
    algorithm: draft.algorithm,
    endpoint: draft.endpoint.trim(),
    bucket: draft.bucket.trim(),
    path_prefix: draft.pathPrefix.trim(),
    region: draft.region.trim(),
    service: draft.service.trim(),
    signature_ttl_seconds: draft.ttl,
    current_credential: { credential_id: draft.credentialID.trim(), revision: draft.credentialRevision },
  }
}

function draftFromRule(rule: OriginAuthRule): RuleDraft {
  return {
    siteID: rule.site_id,
    sourcePosition: rule.source_position,
    provider: rule.provider,
    algorithm: rule.algorithm,
    endpoint: rule.endpoint,
    bucket: rule.bucket,
    pathPrefix: rule.path_prefix,
    region: rule.region,
    service: rule.service,
    ttl: rule.signature_ttl_seconds,
    credentialID: rule.current_credential.credential_id,
    credentialRevision: rule.current_credential.revision,
    enabled: rule.enabled,
  }
}

function validDraft(draft: RuleDraft) {
  return uuidPattern.test(draft.siteID) && uuidPattern.test(draft.credentialID) &&
    Number.isInteger(draft.sourcePosition) && draft.sourcePosition >= 1 && draft.sourcePosition <= 32 &&
    Number.isInteger(draft.credentialRevision) && draft.credentialRevision >= 1 &&
    Number.isInteger(draft.ttl) && draft.ttl >= 1 && draft.ttl <= 3600 &&
    Boolean(draft.endpoint.trim() && draft.bucket.trim() && draft.pathPrefix.trim() && draft.region.trim() && draft.service.trim())
}

export default function OriginAuthRulesPage() {
  const { t } = useTranslation('originAuthRules')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = useMemo(() => principal ? originAuthRuleOwner(principal, sessionEpoch) : null, [principal, sessionEpoch])

  if (!accessToken || !principal) return null
  if (!owner || !canRead(principal)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <OriginAuthRulesContent key={ownerKey} owner={owner} ownerKey={ownerKey} manageable={canManage(principal)} />
}

export function OriginAuthRulesContent({ owner, ownerKey, manageable }: {
  owner: Owner
  ownerKey: string
  manageable: boolean
}) {
  const { t, i18n } = useTranslation('originAuthRules')
  const [messageApi, messageContext] = useFeedbackMessage()
  const queryClient = useQueryClient()
  const [siteDraft, setSiteDraft] = useState('')
  const [siteFilter, setSiteFilter] = useState<string>()
  const [provider, setProvider] = useState<OriginAuthProvider>()
  const [enabled, setEnabled] = useState<boolean>()
  const [cursors, setCursors] = useState<string[]>([])
  const [selectedID, setSelectedID] = useState<string>()
  const [editing, setEditing] = useState<OriginAuthRule | 'create'>()
  const [draft, setDraft] = useState<RuleDraft>(defaultDraft)
  const [draftError, setDraftError] = useState(false)
  const [rotateRule, setRotateRule] = useState<OriginAuthRule>()
  const [rotateCredential, setRotateCredential] = useState('')
  const [rotateRevision, setRotateRevision] = useState(1)
  const [rotateAt, setRotateAt] = useState('')
  const [pendingWrite, setPendingWrite] = useState<PendingWrite>()
  const [writeError, setWriteError] = useState<string>()
  const [writing, setWriting] = useState(false)
  const fixedOwner = useRef(owner).current
  const lineageActive = useRef(true)
  const scopeID = fixedOwner[1]
  const cursor = cursors.at(-1)
  const prefix = useMemo(() => ['origin-auth-rules', ...fixedOwner] as const, [fixedOwner])
  const identity = JSON.stringify([...prefix, siteFilter ?? '', enabled ?? '', cursor ?? ''])
  const activeIdentity = useRef(identity)
  activeIdentity.current = identity

  const guardedRead = useCallback(async <T,>(read: (token: string) => Promise<T>, requestIdentity?: string) => {
    const token = lineageActive.current ? currentOriginAuthRuleAccess(ownerKey) : null
    if (!token) throw staleRead
    try {
      const value = await read(token)
      if (!currentOriginAuthRuleAccess(ownerKey) || (requestIdentity && activeIdentity.current !== requestIdentity)) throw staleRead
      return value
    } catch (error) {
      if (!currentOriginAuthRuleAccess(ownerKey) || (requestIdentity && activeIdentity.current !== requestIdentity)) throw staleRead
      throw error
    }
  }, [ownerKey])

  const listQuery = useQuery({
    queryKey: [...prefix, 'list', siteFilter ?? '', enabled ?? '', cursor ?? ''],
    queryFn: () => guardedRead((token) => originAuthRulesApi.list(token, scopeID, {
      siteID: siteFilter, enabled, limit: 20, cursor,
    }), identity),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })
  const detailQuery = useQuery({
    queryKey: [...prefix, 'detail', selectedID ?? ''],
    queryFn: () => guardedRead((token) => originAuthRulesApi.get(token, scopeID, selectedID!)),
    enabled: Boolean(selectedID),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  useEffect(() => () => {
    lineageActive.current = false
    queryClient.removeQueries({ queryKey: prefix })
  }, [prefix, queryClient])

  const executeWrite = useCallback(async (operation: PendingWrite, successKey = 'notices.updated') => {
    setWriting(true)
    setWriteError(undefined)
    try {
      await operation.run()
      setPendingWrite(undefined)
      await queryClient.invalidateQueries({ queryKey: prefix })
      messageApi.success(t(successKey))
      return true
    } catch (error) {
      if (isUnknownWrite(error)) setPendingWrite(operation)
      else setWriteError(originAuthRuleErrorKey(error))
      return false
    } finally {
      setWriting(false)
    }
  }, [messageApi, prefix, queryClient, t])

  const write = useCallback((call: (token: string) => Promise<OriginAuthRule>): PendingWrite => ({
    run: () => {
      const token = currentOriginAuthRuleAccess(ownerKey)
      if (!token) return Promise.reject(staleRead)
      return call(token)
    },
  }), [ownerKey])

  const applyFilters = () => {
    const value = siteDraft.trim()
    if (value && !uuidPattern.test(value)) {
      setWriteError('validation.site')
      return
    }
    setWriteError(undefined)
    setSiteFilter(value || undefined)
    setCursors([])
    setSelectedID(undefined)
  }

  const openCreate = () => {
    setDraft(defaultDraft)
    setDraftError(false)
    setEditing('create')
  }

  const openEdit = (rule: OriginAuthRule) => {
    setDraft(draftFromRule(rule))
    setDraftError(false)
    setEditing(rule)
  }

  const saveDraft = async () => {
    if (!validDraft(draft)) {
      setDraftError(true)
      return
    }
    const key = operationKey()
    const config = configFromDraft(draft)
    const operation = editing === 'create'
      ? write((token) => originAuthRulesApi.create(token, scopeID, {
        site_id: draft.siteID,
        source_position: draft.sourcePosition,
        config,
        enabled: draft.enabled,
      }, key))
      : write((token) => originAuthRulesApi.update(token, scopeID, editing!.id, { config }, editing!.revision, key))
    if (await executeWrite(operation, 'notices.saved')) setEditing(undefined)
  }

  const deleteRule = (rule: OriginAuthRule) => {
    const key = operationKey()
    void executeWrite(write((token) => originAuthRulesApi.remove(token, scopeID, rule.id, rule.revision, key)), 'notices.deleted')
  }

  const toggleRule = (rule: OriginAuthRule) => {
    const key = operationKey()
    void executeWrite(write((token) => originAuthRulesApi.setEnabled(
      token, scopeID, rule.id, !rule.enabled, rule.revision, key,
    )))
  }

  const rotate = async () => {
    if (!rotateRule || !uuidPattern.test(rotateCredential) || rotateRevision < 1 || !Number.isFinite(Date.parse(rotateAt))) {
      setWriteError('validation.credential')
      return
    }
    const key = operationKey()
    const operation = write((token) => originAuthRulesApi.rotate(token, scopeID, rotateRule.id, {
      current_credential: { credential_id: rotateCredential, revision: rotateRevision },
      activate_current_at: new Date(rotateAt).toISOString(),
    }, rotateRule.revision, key))
    if (await executeWrite(operation)) setRotateRule(undefined)
  }

  const locale = i18n.resolvedLanguage ?? i18n.language
  const items = (listQuery.data?.items ?? []).filter((rule) => provider === undefined || rule.provider === provider)
  const columns: TableColumnsType<OriginAuthRule> = [
    { title: t('fields.site'), dataIndex: 'site_id', width: 270 },
    { title: t('fields.provider'), dataIndex: 'provider', width: 90, render: (value: OriginAuthProvider) => t(`providers.${value}`) },
    { title: t('fields.endpoint'), dataIndex: 'endpoint', width: 250 },
    { title: t('fields.bucket'), dataIndex: 'bucket', width: 130 },
    { title: t('fields.sourcePosition'), dataIndex: 'source_position', width: 100 },
    { title: t('fields.enabled'), dataIndex: 'enabled', width: 90, render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{t(value ? 'states.enabled' : 'states.disabled')}</Tag> },
    { title: t('fields.revision'), dataIndex: 'revision', width: 90 },
    { title: t('fields.updatedAt'), dataIndex: 'updated_at', width: 180, render: (value: string) => new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) },
    {
      title: t('fields.actions'), key: 'actions', width: manageable ? 245 : 60, fixed: 'right',
      render: (_, rule) => <Space size={4}>
        <Tooltip title={t('actions.detail')}><Button aria-label={t('actions.detail')} icon={<Eye size={15} />} onClick={() => setSelectedID(rule.id)} /></Tooltip>
        {manageable ? <>
          <Tooltip title={t('actions.edit')}><Button aria-label={t('actions.edit')} icon={<Pencil size={15} />} onClick={() => openEdit(rule)} /></Tooltip>
          <Button size="small" onClick={() => toggleRule(rule)}>{t(rule.enabled ? 'actions.disable' : 'actions.enable')}</Button>
          <Tooltip title={t('actions.rotate')}><Button aria-label={t('actions.rotate')} icon={<RotateCw size={15} />} onClick={() => { setRotateRule(rule); setRotateCredential(''); setRotateRevision(1); setRotateAt('') }} /></Tooltip>
          <Popconfirm title={t('dialogs.deleteTitle')} okText={t('actions.confirmDelete')} cancelText={t('actions.cancel')} onConfirm={() => deleteRule(rule)}>
            <Tooltip title={t('actions.delete')}><Button danger aria-label={t('actions.delete')} icon={<Trash2 size={15} />} /></Tooltip>
          </Popconfirm>
        </> : null}
      </Space>,
    },
  ]

  if (isForbidden(listQuery.error)) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }

  return <section className="identity-page" aria-labelledby="origin-auth-rules-title">
    {messageContext}
    <header className="identity-page-header">
      <div>
        <Typography.Title id="origin-auth-rules-title" level={2}>{t('title')}</Typography.Title>
        <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      </div>
      <Space>
        {!manageable ? <Tag>{t('readOnly')}</Tag> : <Button type="primary" icon={<Plus size={16} />} onClick={openCreate}>{t('actions.create')}</Button>}
        <Button icon={<RefreshCw size={16} />} loading={listQuery.isFetching} onClick={() => void listQuery.refetch()}>{t('actions.refresh')}</Button>
      </Space>
    </header>

    <Space wrap className="identity-toolbar">
      <Input aria-label={t('filters.site')} value={siteDraft} onChange={(event) => setSiteDraft(event.target.value)} onPressEnter={applyFilters} />
      <Select aria-label={t('filters.provider')} allowClear value={provider} placeholder={t('filters.all')} style={{ width: 170 }} onChange={setProvider} options={(['s3', 'oss', 'cos'] as const).map((value) => ({ value, label: t(`providers.${value}`) }))} />
      <Select aria-label={t('filters.enabled')} allowClear value={enabled} placeholder={t('filters.all')} style={{ width: 150 }} onChange={setEnabled} options={[{ value: true, label: t('states.enabled') }, { value: false, label: t('states.disabled') }]} />
      <Button type="primary" onClick={applyFilters}>{t('filters.query')}</Button>
    </Space>
    {writeError ? <div role="alert" className="data-state data-state-error">{t(writeError)}</div> : null}

    {listQuery.isPending ? <DataState status="loading" message={t('data.loading')} /> : listQuery.isError ? (
      <DataState status="error" message={t(originAuthRuleErrorKey(listQuery.error))} onRetry={() => void listQuery.refetch()} />
    ) : items.length === 0 ? <DataState status="empty" message={t('data.empty')} /> : (
      <div aria-busy={listQuery.isFetching}><Table rowKey="id" size="small" columns={columns} dataSource={items} pagination={false} scroll={{ x: 1450 }} /></div>
    )}
    <footer className="identity-pagination">
      <Button aria-label={t('actions.previous')} icon={<ChevronLeft size={16} />} disabled={!cursors.length || listQuery.isFetching} onClick={() => setCursors((value) => value.slice(0, -1))} />
      <span>{t('pagination.page', { page: cursors.length + 1 })}</span>
      <Button aria-label={t('actions.next')} icon={<ChevronRight size={16} />} disabled={!listQuery.data?.next_cursor || listQuery.isFetching} onClick={() => { if (listQuery.data?.next_cursor) setCursors((value) => [...value, listQuery.data!.next_cursor!]) }} />
    </footer>

    <Drawer title={t('dialogs.detail')} width={650} open={Boolean(selectedID)} onClose={() => setSelectedID(undefined)}>
      {detailQuery.isPending ? <DataState status="loading" message={t('data.detailLoading')} /> : isForbidden(detailQuery.error) ? (
        <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} />
      ) : detailQuery.isError ? <DataState status="error" message={t(originAuthRuleErrorKey(detailQuery.error))} onRetry={detailQuery.error instanceof ApiError && detailQuery.error.status === 404 ? undefined : () => void detailQuery.refetch()} /> : detailQuery.data ? (
        <Descriptions bordered size="small" column={1}>
          <Descriptions.Item label={t('fields.site')}>{detailQuery.data.site_id}</Descriptions.Item>
          <Descriptions.Item label={t('fields.endpoint')}>{detailQuery.data.endpoint}</Descriptions.Item>
          <Descriptions.Item label={t('fields.bucket')}>{detailQuery.data.bucket}</Descriptions.Item>
          <Descriptions.Item label={t('fields.credentialID')}>{detailQuery.data.current_credential.credential_id}</Descriptions.Item>
          <Descriptions.Item label={t('fields.revision')}>{detailQuery.data.revision}</Descriptions.Item>
        </Descriptions>
      ) : null}
    </Drawer>

    <Drawer title={t(editing === 'create' ? 'dialogs.create' : 'dialogs.edit')} width={620} open={Boolean(editing)} onClose={() => setEditing(undefined)} extra={<Space><Button onClick={() => setEditing(undefined)}>{t('actions.cancel')}</Button><Button type="primary" loading={writing} onClick={() => void saveDraft()}>{t('actions.save')}</Button></Space>}>
      <Form layout="vertical">
        <Form.Item label={t('fields.createSite')} validateStatus={draftError && !uuidPattern.test(draft.siteID) ? 'error' : undefined}><Input aria-label={t('fields.createSite')} value={draft.siteID} disabled={editing !== 'create'} onChange={(event) => setDraft((value) => ({ ...value, siteID: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.sourcePosition')}><InputNumber aria-label={t('fields.sourcePosition')} min={1} max={32} value={draft.sourcePosition} onChange={(value) => setDraft((current) => ({ ...current, sourcePosition: value ?? 1 }))} /></Form.Item>
        <Form.Item label={t('fields.provider')}><Select aria-label={t('fields.provider')} value={draft.provider} onChange={(value) => setDraft((current) => ({ ...current, provider: value }))} options={(['s3', 'oss', 'cos'] as const).map((value) => ({ value, label: t(`providers.${value}`) }))} /></Form.Item>
        <Form.Item label={t('fields.algorithm')}><Select aria-label={t('fields.algorithm')} value={draft.algorithm} onChange={(value) => setDraft((current) => ({ ...current, algorithm: value }))} options={(['aws4-hmac-sha256', 'oss4-hmac-sha256', 'cos-hmac-sha1'] as const).map((value) => ({ value, label: t(`algorithms.${value}`) }))} /></Form.Item>
        <Form.Item label={t('fields.endpoint')}><Input aria-label={t('fields.endpoint')} value={draft.endpoint} onChange={(event) => setDraft((value) => ({ ...value, endpoint: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.bucket')}><Input aria-label={t('fields.bucket')} value={draft.bucket} onChange={(event) => setDraft((value) => ({ ...value, bucket: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.pathPrefix')}><Input aria-label={t('fields.pathPrefix')} value={draft.pathPrefix} onChange={(event) => setDraft((value) => ({ ...value, pathPrefix: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.region')}><Input aria-label={t('fields.region')} value={draft.region} onChange={(event) => setDraft((value) => ({ ...value, region: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.service')}><Input aria-label={t('fields.service')} value={draft.service} onChange={(event) => setDraft((value) => ({ ...value, service: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.ttl')}><InputNumber aria-label={t('fields.ttl')} min={1} max={3600} value={draft.ttl} onChange={(value) => setDraft((current) => ({ ...current, ttl: value ?? 1 }))} /></Form.Item>
        <Form.Item label={t('fields.credentialID')} validateStatus={draftError && !uuidPattern.test(draft.credentialID) ? 'error' : undefined}><Input aria-label={t('fields.credentialID')} value={draft.credentialID} onChange={(event) => setDraft((value) => ({ ...value, credentialID: event.target.value }))} /></Form.Item>
        <Form.Item label={t('fields.credentialRevision')}><InputNumber aria-label={t('fields.credentialRevision')} min={1} value={draft.credentialRevision} onChange={(value) => setDraft((current) => ({ ...current, credentialRevision: value ?? 1 }))} /></Form.Item>
        {editing === 'create' ? <Form.Item><Checkbox checked={draft.enabled} onChange={(event) => setDraft((value) => ({ ...value, enabled: event.target.checked }))}>{t('fields.enabled')}</Checkbox></Form.Item> : null}
        {draftError ? <div role="alert" className="data-state data-state-error">{t('validation.required')}</div> : null}
      </Form>
    </Drawer>

    <Modal title={t('dialogs.rotate')} open={Boolean(rotateRule)} confirmLoading={writing} okText={t('actions.save')} cancelText={t('actions.cancel')} onOk={() => void rotate()} onCancel={() => setRotateRule(undefined)}>
      <Form layout="vertical">
        <Form.Item label={t('fields.credentialID')}><Input value={rotateCredential} onChange={(event) => setRotateCredential(event.target.value)} /></Form.Item>
        <Form.Item label={t('fields.credentialRevision')}><InputNumber min={1} value={rotateRevision} onChange={(value) => setRotateRevision(value ?? 1)} /></Form.Item>
        <Form.Item label={t('fields.activateAt')}><Input type="datetime-local" value={rotateAt} onChange={(event) => setRotateAt(event.target.value)} /></Form.Item>
      </Form>
    </Modal>

    <Modal title={t('dialogs.unknownTitle')} open={Boolean(pendingWrite)} closable={false} destroyOnHidden footer={<Space><Button onClick={() => setPendingWrite(undefined)}>{t('actions.abandon')}</Button><Button type="primary" loading={writing} onClick={() => { if (pendingWrite) void executeWrite(pendingWrite) }}>{t('actions.exactRetry')}</Button></Space>}>
      <Typography.Paragraph>{t('dialogs.unknownDescription')}</Typography.Paragraph>
    </Modal>
  </section>
}
