import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Popconfirm, Result, Space,
  Spin, Table, Tag, Typography,
  type TableColumnsType,
} from 'antd'
import { RefreshCw, Send } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  createOriginAuthEdgePublicationWriteMetadata,
  createOriginAuthPublicationWriteMetadata,
  originAuthPublicationsApi,
  type OriginAuthEdgePublication,
  type OriginAuthEdgePublicationWriteMetadata,
  type OriginAuthPublication,
  type OriginAuthPublicationRule,
  type OriginAuthPublicationWriteMetadata,
  type PublishOriginAuthEdgePublicationInput,
} from '../api/originAuthPublications'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { localizedUnknownApiError } from '../i18n/apiError'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/originAuthPublications'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly [Principal['scope_kind'], string, string | null, string, number]
interface PublishAttempt {
  expectedRevision: number
  metadata: OriginAuthPublicationWriteMetadata
  baseline: OriginAuthPublication | null
}
interface EdgePublishAttempt {
  sourceRevision: number
  input: PublishOriginAuthEdgePublicationInput
  metadata: OriginAuthEdgePublicationWriteMetadata
}
interface SnapshotComparison { added: number; removed: number; changed: number; unchanged: number }

const queryRoot = 'origin-auth-publications'
const staleRead = new Error('Origin authentication publication owner changed during read')
const canonicalUUIDPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const localizedErrorCodes = new Set([
  'network_error', 'invalid_response', 'invalid_request', 'authentication_required',
  'permission_denied', 'entitlement_denied', 'not_found', 'resource_conflict',
  'idempotency_conflict', 'revision_conflict', 'validation_error', 'request_canceled',
  'service_unavailable',
])

function identityForOriginAuthPublication(principal: Principal, sessionEpoch: number): Owner | null {
  const { scope_id: scopeID, tenant_id: tenantID, user_id: userID } = principal
  if (!scopeID || scopeID.trim() !== scopeID || !userID || userID.trim() !== userID || sessionEpoch < 1) return null
  if (principal.scope_kind === 'tenant' && (
    !tenantID || tenantID.trim() !== tenantID
  )) return null
  if (principal.scope_kind === 'platform' && tenantID !== null) return null
  return [principal.scope_kind, scopeID, tenantID, userID, sessionEpoch]
}

type OriginAuthPermission = 'origin_auth.read' | 'origin_auth.manage' | 'edge_publications.read' | 'edge_publications.manage'

function hasPermission(principal: Principal, permission: OriginAuthPermission): boolean {
  return principal.permissions.includes(permission)
}

function currentAccess(ownerKey: string, permissions: readonly OriginAuthPermission[]): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !permissions.every((permission) => hasPermission(principal, permission))) return null
  const owner = identityForOriginAuthPublication(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 503 || error.status === 504 || error.code === 'invalid_response'
}

function errorMessage(
  error: unknown,
  t: ReturnType<typeof useTranslation<'originAuthPublications'>>['t'],
): string {
  return error instanceof ApiError && localizedErrorCodes.has(error.code)
    ? t(`errors.${error.code}`)
    : localizedUnknownApiError(error, t('errors.requestFailed'))
}

function edgeErrorMessage(
  error: unknown,
  t: ReturnType<typeof useTranslation<'originAuthPublications'>>['t'],
): string {
  if (!(error instanceof ApiError)) return t('errors.edge_unavailable')
  if (error.code === 'origin_auth_edge_publication_permission_denied' || error.status === 403) {
    return t('errors.edge_permission_denied')
  }
  if (error.code === 'origin_auth_edge_publication_invalid_request' || error.status === 400) {
    return t('errors.edge_invalid_request')
  }
  if (error.code === 'origin_auth_edge_publication_invalid_response' || error.status === 502) {
    return t('errors.edge_invalid_response')
  }
  if (error.code === 'origin_auth_edge_publication_outcome_unknown') return t('errors.edge_outcome_unknown')
  return t('errors.edge_unavailable')
}

function edgeOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 ||
    error.status === 504 || error.code === 'origin_auth_edge_publication_outcome_unknown'
}

function compareSnapshots(
  previous: OriginAuthPublication | null,
  current: OriginAuthPublication,
): SnapshotComparison {
  const before = new Map(previous?.snapshot.rules.map((rule) => [rule.rule_id, rule]) ?? [])
  const after = new Map(current.snapshot.rules.map((rule) => [rule.rule_id, rule]))
  let added = 0
  let removed = 0
  let changed = 0
  let unchanged = 0
  for (const [id, rule] of after) {
    const old = before.get(id)
    if (!old) added += 1
    else if (JSON.stringify(old) === JSON.stringify(rule)) unchanged += 1
    else changed += 1
  }
  for (const id of before.keys()) if (!after.has(id)) removed += 1
  return { added, removed, changed, unchanged }
}

function endpointHost(endpoint: string): string {
  return new URL(endpoint).host
}

function OriginAuthPublicationsContent({
  owner,
  scopeID,
  edgeRead,
  edgeManage,
}: {
  owner: Owner
  scopeID: string
  edgeRead: boolean
  edgeManage: boolean
}) {
  const { t, i18n } = useTranslation('originAuthPublications')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const fixedScopeID = useRef(scopeID).current
  const ownerKey = JSON.stringify(fixedOwner)
  const prefix = useMemo(() => [queryRoot, ...fixedOwner, fixedScopeID] as const, [fixedOwner, fixedScopeID])
  const queryKey = useMemo(() => [...prefix, 'latest'] as const, [prefix])
  const lineageActiveRef = useRef(true)
  const [attempt, setAttempt] = useState<PublishAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const [manageForbidden, setManageForbidden] = useState(false)
  const [comparison, setComparison] = useState<SnapshotComparison | null>(null)
  const [edgeDialogOpen, setEdgeDialogOpen] = useState(false)
  const [edgeNodeIDs, setEdgeNodeIDs] = useState('')
  const [edgeActivationTimeout, setEdgeActivationTimeout] = useState<number | null>(30_000)
  const [edgeObservationWindow, setEdgeObservationWindow] = useState<number | null>(10_000)
  const [edgeRequiredSuccesses, setEdgeRequiredSuccesses] = useState<number | null>(3)
  const [edgeDeadline, setEdgeDeadline] = useState('')
  const [edgeAttempt, setEdgeAttempt] = useState<EdgePublishAttempt | null>(null)
  const [edgeWriteError, setEdgeWriteError] = useState<unknown>(null)
  const [edgeReadError, setEdgeReadError] = useState<unknown>(null)
  const [edgePending, setEdgePending] = useState(false)
  const [edgeReadPending, setEdgeReadPending] = useState(false)
  const [edgePublicationID, setEdgePublicationID] = useState('')
  const [edgePublication, setEdgePublication] = useState<OriginAuthEdgePublication | null>(null)
  const edgeReadAbortRef = useRef<AbortController | null>(null)
  const currentSessionAccess = useCallback(
    (permissions: readonly OriginAuthPermission[]) => (
      lineageActiveRef.current ? currentAccess(ownerKey, permissions) : null
    ),
    [ownerKey],
  )

  const query = useQuery({
    queryKey,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
    queryFn: async ({ signal }) => {
      const token = currentSessionAccess(['origin_auth.read'])
      if (!token) throw staleRead
      try {
        const result = await originAuthPublicationsApi.getLatest(token, fixedScopeID, signal)
        if (!currentSessionAccess(['origin_auth.read'])) throw staleRead
        return result
      } catch (error) {
        if (!currentSessionAccess(['origin_auth.read'])) throw staleRead
        throw error
      }
    },
  })

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      edgeReadAbortRef.current?.abort()
      void queryClient.cancelQueries({ queryKey: prefix })
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [prefix, queryClient])

  const executePublish = async (nextAttempt: PublishAttempt) => {
    if (writePending) return
    if (manageForbidden) return
    const token = currentSessionAccess(['origin_auth.manage'])
    if (!token) return
    setWritePending(true)
    setWriteError(null)
    try {
      const result = await originAuthPublicationsApi.create(
        token, fixedScopeID, nextAttempt.expectedRevision, nextAttempt.metadata,
      )
      if (!currentSessionAccess(['origin_auth.manage'])) return
      queryClient.setQueryData(queryKey, result)
      setComparison(compareSnapshots(nextAttempt.baseline, result))
      setAttempt(null)
    } catch (error) {
      if (!currentSessionAccess(['origin_auth.manage'])) return
      if (error instanceof ApiError && error.status === 403) {
        setManageForbidden(true)
        setAttempt(null)
      }
      setWriteError(error)
      if (!outcomeUnknown(error)) setAttempt(null)
    } finally {
      if (currentSessionAccess(['origin_auth.manage'])) setWritePending(false)
    }
  }

  const publish = () => {
    if (writePending || attempt || manageForbidden) return
    const baseline = query.data ?? null
    const nextAttempt: PublishAttempt = {
      expectedRevision: baseline?.revision ?? 0,
      metadata: createOriginAuthPublicationWriteMetadata(),
      baseline,
    }
    setAttempt(nextAttempt)
    void executePublish(nextAttempt)
  }

  const abandon = () => {
    setAttempt(null)
    setWriteError(null)
    setWritePending(false)
    void query.refetch()
  }

  const readEdgePublication = async (publicationID: string) => {
    const token = currentSessionAccess(['origin_auth.read', 'edge_publications.read'])
    if (!token || !edgeRead) return
    edgeReadAbortRef.current?.abort()
    const controller = new AbortController()
    edgeReadAbortRef.current = controller
    setEdgeReadPending(true)
    setEdgeReadError(null)
    try {
      const result = await originAuthPublicationsApi.getEdgePublication(
        token, fixedScopeID, publicationID, crypto.randomUUID(), controller.signal,
      )
      if (!currentSessionAccess(['origin_auth.read', 'edge_publications.read'])) return
      setEdgePublication(result)
    } catch (error) {
      if (!currentSessionAccess(['origin_auth.read', 'edge_publications.read']) || controller.signal.aborted) return
      setEdgeReadError(error)
    } finally {
      if (currentSessionAccess(['origin_auth.read', 'edge_publications.read'])) setEdgeReadPending(false)
    }
  }

  const executeEdgePublish = async (nextAttempt: EdgePublishAttempt) => {
    if (edgePending) return
    const token = currentSessionAccess(['origin_auth.manage', 'edge_publications.manage'])
    if (!token || !edgeManage) return
    setEdgePending(true)
    setEdgeWriteError(null)
    setEdgeReadError(null)
    setEdgePublication(null)
    try {
      const receipt = await originAuthPublicationsApi.publishToNodes(
        token, fixedScopeID, nextAttempt.sourceRevision, nextAttempt.input, nextAttempt.metadata,
      )
      if (!currentSessionAccess(['origin_auth.manage', 'edge_publications.manage'])) return
      setEdgeAttempt(null)
      setEdgePublicationID(receipt.publication_id)
      await readEdgePublication(receipt.publication_id)
    } catch (error) {
      if (!currentSessionAccess(['origin_auth.manage', 'edge_publications.manage'])) return
      setEdgeWriteError(error)
      if (!edgeOutcomeUnknown(error)) setEdgeAttempt(null)
    } finally {
      if (currentSessionAccess(['origin_auth.manage', 'edge_publications.manage'])) setEdgePending(false)
    }
  }

  const openEdgePublish = () => {
    setEdgeNodeIDs('')
    setEdgeActivationTimeout(30_000)
    setEdgeObservationWindow(10_000)
    setEdgeRequiredSuccesses(3)
    setEdgeDeadline('')
    setEdgeDialogOpen(true)
  }

  const submitEdgePublish = () => {
    if (!query.data || edgePending || edgeAttempt) return
    if (edgeActivationTimeout === null || edgeObservationWindow === null || edgeRequiredSuccesses === null) {
      setEdgeWriteError(new ApiError(
        'Invalid node publication health check', 400, 'origin_auth_edge_publication_invalid_request',
      ))
      return
    }
    const nodeIDs = edgeNodeIDs.split(/[\s,]+/u).filter(Boolean)
    const input = Object.freeze({
      node_ids: Object.freeze(nodeIDs),
      health_check: Object.freeze({
        activation_timeout_ms: edgeActivationTimeout,
        observation_window_ms: edgeObservationWindow,
        required_consecutive_successes: edgeRequiredSuccesses,
      }),
      deadline: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(edgeDeadline) ? `${edgeDeadline}:00Z` : edgeDeadline,
    })
    const nextAttempt = Object.freeze({
      sourceRevision: query.data.revision,
      input,
      metadata: Object.freeze(createOriginAuthEdgePublicationWriteMetadata()),
    })
    setEdgeAttempt(nextAttempt)
    setEdgeDialogOpen(false)
    void executeEdgePublish(nextAttempt)
  }

  const abandonEdgePublish = () => {
    setEdgeAttempt(null)
    setEdgeWriteError(null)
    setEdgePending(false)
    void query.refetch()
  }

  const error = query.error instanceof ApiError ? query.error : null
  if (error?.status === 403) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }

  const publication = query.data
  const noPublication = error?.status === 404
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const canPublish = !manageForbidden && Boolean(currentAccess(ownerKey, ['origin_auth.manage']))
  const canPublishEdge = fixedOwner[0] === 'platform' && edgeRead && edgeManage && Boolean(publication) &&
    Boolean(currentAccess(ownerKey, ['origin_auth.manage', 'edge_publications.manage']))
  const locale = i18n.resolvedLanguage ?? i18n.language
  const columns: TableColumnsType<OriginAuthPublicationRule> = [
    { title: t('columns.site'), dataIndex: 'site_id', width: 270, ellipsis: true },
    { title: t('columns.source'), dataIndex: 'source_position', width: 100 },
    { title: t('columns.provider'), dataIndex: 'provider', width: 120, render: (value) => <Tag>{t(`providers.${value}`)}</Tag> },
    { title: t('columns.endpoint'), dataIndex: 'endpoint', width: 220, render: endpointHost },
    { title: t('columns.bucket'), dataIndex: 'bucket', width: 160, ellipsis: true },
    { title: t('columns.path'), dataIndex: 'path_prefix', width: 160, ellipsis: true },
    { title: t('columns.algorithm'), dataIndex: 'algorithm', width: 190, render: (value) => t(`algorithms.${value}`) },
    { title: t('columns.ttl'), dataIndex: 'signature_ttl_seconds', width: 110, render: (value) => t('seconds', { count: value }) },
    {
      title: t('columns.activation'), dataIndex: 'activate_current_at_unix', width: 190,
      render: (value) => formatDateTime(new Date(value * 1000).toISOString(), locale),
    },
  ]

  return (
    <section className="identity-page origin-auth-publications-page">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        <Space wrap>
          <Button
            icon={<RefreshCw size={16} aria-hidden="true" />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            {t('actions.refresh')}
          </Button>
          {canPublish ? (
            <Popconfirm
              title={t('confirmations.publish')}
              okText={t('actions.confirmPublish')}
              onConfirm={publish}
            >
              <Button type="primary" icon={<Send size={16} aria-hidden="true" />} disabled={writePending || Boolean(attempt)}>
                {t('actions.publish')}
              </Button>
            </Popconfirm>
          ) : null}
          {canPublishEdge ? (
            <Button
              icon={<Send size={16} aria-hidden="true" />}
              disabled={edgePending || Boolean(edgeAttempt)}
              onClick={openEdgePublish}
            >
              {t('edge.actions.publish')}
            </Button>
          ) : null}
        </Space>
      </header>

      {uncertain ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap>
            <Button type="primary" loading={writePending} onClick={() => attempt && void executePublish(attempt)}>
              {t('actions.retrySameRequest')}
            </Button>
            <Button disabled={writePending} onClick={abandon}>{t('actions.abandonRefresh')}</Button>
          </Space>} className="identity-alert" />
      ) : writeError ? (
        <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} />
      ) : null}

      {comparison ? (
        <Alert
          className="identity-alert"
          type="success"
          showIcon
          message={t('comparison.title')}
          description={t('comparison.summary', {
            added: comparison.added,
            removed: comparison.removed,
            changed: comparison.changed,
            unchanged: comparison.unchanged,
          })}
        />
      ) : null}

      {query.isPending && !publication ? (
        <DataState status="loading" message={t('loading')} />
      ) : noPublication ? (
        <DataState status="empty" message={t('empty')} />
      ) : query.isError ? (
        <DataState status="error" message={errorMessage(query.error, t)} onRetry={() => void query.refetch()} />
      ) : publication ? (
        <>
          <Space wrap className="identity-toolbar">
            <Typography.Title level={3}>{t('version', { revision: publication.revision })}</Typography.Title>
            <Tag>{t('rulesCount', { count: publication.snapshot.rules.length })}</Tag>
          </Space>
          <Descriptions size="small" bordered column={{ xs: 1, md: 2 }}>
            <Descriptions.Item label={t('details.createdAt')}>
              {formatDateTime(publication.created_at, locale)}
            </Descriptions.Item>
            <Descriptions.Item label={t('details.snapshotHash')}>
              <Typography.Text copyable>{publication.snapshot_hash}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label={t('details.previousHash')}>
              {publication.previous_hash
                ? <Typography.Text copyable>{publication.previous_hash}</Typography.Text>
                : t('details.noPrevious')}
            </Descriptions.Item>
          </Descriptions>
          <Table<OriginAuthPublicationRule>
            rowKey="rule_id"
            size="small"
            columns={columns}
            dataSource={publication.snapshot.rules}
            pagination={false}
            scroll={{ x: 1_600 }}
          />
        </>
      ) : null}

      {fixedOwner[0] === 'platform' ? edgeRead ? (
        <div className="origin-auth-edge-publication">
          {edgeAttempt && edgeWriteError && edgeOutcomeUnknown(edgeWriteError) ? (
            <OutcomeUnknown title={t('edge.uncertainty.title')} detail={t('edge.uncertainty.description')} action={<Space wrap>
                <Button
                  type="primary"
                  loading={edgePending}
                  onClick={() => void executeEdgePublish(edgeAttempt)}
                >
                  {t('edge.actions.retrySameRequest')}
                </Button>
                <Button disabled={edgePending} onClick={abandonEdgePublish}>
                  {t('edge.actions.abandonRefresh')}
                </Button>
              </Space>} className="identity-alert" />
          ) : edgeWriteError ? (
            <FeedbackWhen title={edgeErrorMessage(edgeWriteError, t)} />
          ) : edgeReadError ? (
            <FeedbackWhen title={edgeErrorMessage(edgeReadError, t)} action={<Button onClick={() => void readEdgePublication(edgePublicationID)}>
                {t('edge.actions.retryRead')}
              </Button>} />
          ) : null}

          {edgePending || edgeReadPending ? (
            <Space><Spin size="small" /><Typography.Text>{t('edge.loading')}</Typography.Text></Space>
          ) : edgePublication ? (
            <>
              <Typography.Title level={3}>{t('edge.title')}</Typography.Title>
              <Descriptions size="small" bordered column={{ xs: 1, md: 2 }}>
                <Descriptions.Item label={t('edge.details.publicationID')}>
                  <Typography.Text copyable>{edgePublication.publication_id}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.rolloutID')}>
                  <Typography.Text copyable>{edgePublication.rollout_id}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.configVersionID')}>
                  <Typography.Text copyable>{edgePublication.config_version_id}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.configSnapshotHash')}>
                  <Typography.Text copyable>{edgePublication.config_snapshot_sha256}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.artifactManifestHash')}>
                  <Typography.Text copyable>{edgePublication.artifact_manifest_sha256}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.recipientBindingHash')}>
                  <Typography.Text copyable>{edgePublication.recipient_binding_sha256}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('edge.details.createdAt')}>
                  {formatDateTime(edgePublication.created_at, locale)}
                </Descriptions.Item>
                <Descriptions.Item>{t('edge.nodeCount', { count: edgePublication.node_count })}</Descriptions.Item>
              </Descriptions>
            </>
          ) : !edgeWriteError && !edgeReadError ? (
            <DataState status="empty" message={t('edge.empty')} />
          ) : null}
        </div>
      ) : (
        <Result status="403" title={t('edge.forbidden.title')} subTitle={t('edge.forbidden.description')} />
      ) : null}

      <Modal
        title={t('edge.dialogTitle')}
        open={edgeDialogOpen}
        okText={t('edge.actions.confirmPublish')}
        cancelText={t('edge.actions.cancel')}
        onOk={submitEdgePublish}
        onCancel={() => setEdgeDialogOpen(false)}
      >
        <Form layout="vertical">
          <Form.Item label={t('edge.fields.nodeIDs')}>
            <Input.TextArea
              aria-label={t('edge.fields.nodeIDs')}
              value={edgeNodeIDs}
              onChange={(event) => setEdgeNodeIDs(event.target.value)}
            />
          </Form.Item>
          <Form.Item label={t('edge.fields.activationTimeout')}>
            <InputNumber
              aria-label={t('edge.fields.activationTimeout')}
              min={1}
              max={300_000}
              value={edgeActivationTimeout}
              onChange={setEdgeActivationTimeout}
            />
          </Form.Item>
          <Form.Item label={t('edge.fields.observationWindow')}>
            <InputNumber
              aria-label={t('edge.fields.observationWindow')}
              min={1}
              max={300_000}
              value={edgeObservationWindow}
              onChange={setEdgeObservationWindow}
            />
          </Form.Item>
          <Form.Item label={t('edge.fields.requiredSuccesses')}>
            <InputNumber
              aria-label={t('edge.fields.requiredSuccesses')}
              min={1}
              max={100}
              value={edgeRequiredSuccesses}
              onChange={setEdgeRequiredSuccesses}
            />
          </Form.Item>
          <Form.Item label={t('edge.fields.deadline')}>
            <Input
              type="datetime-local"
              aria-label={t('edge.fields.deadline')}
              value={edgeDeadline}
              onChange={(event) => setEdgeDeadline(event.target.value)}
            />
          </Form.Item>
        </Form>
      </Modal>
    </section>
  )
}

export default function OriginAuthPublicationsPage() {
  const { t } = useTranslation('originAuthPublications')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const [searchParams, setSearchParams] = useSearchParams()
  const owner = useMemo(
    () => principal ? identityForOriginAuthPublication(principal, sessionEpoch) : null,
    [principal, sessionEpoch],
  )
  const isPlatform = principal?.scope_kind === 'platform'
  const requestedTarget = isPlatform ? (searchParams.get('target_scope_id') ?? '') : ''
  const targetScopeID = canonicalUUIDPattern.test(requestedTarget) ? requestedTarget : ''
  const [targetScopeDraft, setTargetScopeDraft] = useState(requestedTarget)
  const [targetScopeError, setTargetScopeError] = useState(Boolean(requestedTarget && !targetScopeID))

  useEffect(() => {
    if (!isPlatform) return
    setTargetScopeDraft(requestedTarget)
    setTargetScopeError(Boolean(requestedTarget && !targetScopeID))
  }, [isPlatform, requestedTarget, targetScopeID])

  if (!accessToken || !principal) return null
  if (!owner || !hasPermission(principal, 'origin_auth.read')) {
    return <Result status="403" title={t('forbidden.title')} subTitle={t('forbidden.description')} />
  }
  const applyTargetScope = () => {
    if (!canonicalUUIDPattern.test(targetScopeDraft)) {
      setTargetScopeError(true)
      return
    }
    setTargetScopeError(false)
    setSearchParams({ target_scope_id: targetScopeDraft }, { replace: true })
  }
  const scopeID = isPlatform ? targetScopeID : principal.scope_id
  const edgeRead = isPlatform && hasPermission(principal, 'edge_publications.read')
  const edgeManage = isPlatform && hasPermission(principal, 'edge_publications.manage')

  return (
    <>
      {isPlatform ? (
        <>
          <Space wrap className="identity-toolbar">
            <Input
              aria-label={t('targetScope.label')}
              placeholder={t('targetScope.placeholder')}
              value={targetScopeDraft}
              status={targetScopeError ? 'error' : undefined}
              onChange={(event) => setTargetScopeDraft(event.target.value)}
              onPressEnter={applyTargetScope}
            />
            <Button type="primary" onClick={applyTargetScope}>{t('targetScope.apply')}</Button>
          </Space>
          {!targetScopeID ? (
            <Alert
              className="identity-alert"
              type={targetScopeError ? 'error' : 'info'}
              showIcon
              message={t(targetScopeError ? 'targetScope.invalid' : 'targetScope.required')}
            />
          ) : null}
        </>
      ) : null}
      {scopeID ? (
        <OriginAuthPublicationsContent
          key={`${JSON.stringify(owner)}:${scopeID}`}
          owner={owner}
          scopeID={scopeID}
          edgeRead={edgeRead}
          edgeManage={edgeManage}
        />
      ) : null}
    </>
  )
}
