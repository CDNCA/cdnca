import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Descriptions, Form, Input, InputNumber, Modal, Result, Space, Tag, Typography } from 'antd'
import { Plus, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  createJA4BlockWriteMetadata,
  ja4BlocksApi,
  type AdminJA4BlockCreateInput,
  type JA4BlockCreateInput,
  type JA4BlockWorkflow,
  type JA4BlockWriteMetadata,
} from '../api/ja4Blocks'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import '../i18n/ja4Blocks'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

type Owner = readonly [Principal['scope_kind'], string, string | null, string, number]
type CreateAttempt = Readonly<{
  admin: boolean
  scopeID: string
  input: Readonly<JA4BlockCreateInput | AdminJA4BlockCreateInput>
  metadata: Readonly<JA4BlockWriteMetadata>
}>

const uuidPattern = /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const ja4Pattern = /^[A-Za-z0-9_+.-]{1,128}$/
const reasonPattern = /^[a-z][a-z0-9_]{0,63}$/

function ownerFor(principal: Principal, epoch: number): Owner | null {
  if (!principal.scope_id || principal.scope_id.trim() !== principal.scope_id ||
    !principal.user_id || principal.user_id.trim() !== principal.user_id || epoch < 1 ||
    !principal.permissions.includes('security_policies.read') ||
    !principal.permissions.includes('security_policies.manage')) return null
  if (principal.scope_kind === 'tenant') {
    if (!principal.tenant_id || !uuidPattern.test(principal.scope_id)) return null
  } else if (principal.tenant_id !== null || !principal.permissions.includes('platform.admin')) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, epoch]
}

function currentToken(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function outcomeUnknown(error: unknown): boolean {
  return error instanceof ApiError && (
    error.status === 0 || error.status === 408 || error.status === 503 || error.status === 504 ||
    error.code === 'network_error'
  )
}

function writeErrorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 403 || error.code === 'ja4_block_permission_denied') return 'errors.permissionDenied'
  if (error.status === 409 || error.code === 'ja4_block_idempotency_conflict') return 'errors.idempotencyConflict'
  if (error.status === 412 || error.code === 'ja4_block_revision_conflict') return 'errors.revisionConflict'
  if (error.status === 428 || error.code === 'ja4_block_step_up_required') return 'errors.stepUpRequired'
  if (error.status === 400 || error.code === 'invalid_request') return 'errors.invalidInput'
  if (error.status === 503) return 'errors.unavailable'
  return 'errors.requestFailed'
}

export default function JA4BlockWorkflowsPage() {
  const { t } = useTranslation('ja4Blocks')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  if (!accessToken || !principal) return null
  const owner = ownerFor(principal, epoch)
  if (!owner) return <Result status="403" title="403" subTitle={t('states.forbidden')} />
  const ownerKey = JSON.stringify(owner)
  return <JA4BlockWorkflowsContent key={ownerKey} owner={owner} ownerKey={ownerKey} />
}

function JA4BlockWorkflowsContent({ owner, ownerKey }: { owner: Owner; ownerKey: string }) {
  const { t } = useTranslation('ja4Blocks')
  const activeRef = useRef(true)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [tenantScopeID, setTenantScopeID] = useState('')
  const [siteID, setSiteID] = useState('')
  const [ja4, setJA4] = useState('')
  const [snapshotAt, setSnapshotAt] = useState('')
  const [durationSeconds, setDurationSeconds] = useState<number | null>(3600)
  const [reason, setReason] = useState('')
  const [stepUp, setStepUp] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState<CreateAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)
  const [writeForbidden, setWriteForbidden] = useState(false)
  const [workflow, setWorkflow] = useState<JA4BlockWorkflow | null>(null)
  const [workflowID, setWorkflowID] = useState('')
  const [workflowScopeID, setWorkflowScopeID] = useState('')
  const [readPending, setReadPending] = useState(false)
  const [readError, setReadError] = useState<unknown>(null)

  useEffect(() => () => { activeRef.current = false }, [])

  const resetDraft = () => {
    setTenantScopeID('')
    setSiteID('')
    setJA4('')
    setSnapshotAt('')
    setDurationSeconds(3600)
    setReason('')
    setStepUp('')
    setFormError(null)
  }

  const openDialog = () => {
    resetDraft()
    setDialogOpen(true)
  }

  const readWorkflow = async (id: string, scopeID: string) => {
    const token = currentToken(ownerKey)
    if (!token) return
    setReadPending(true)
    setReadError(null)
    try {
      const requestID = `ja4-block-read-${crypto.randomUUID()}`
      const result = owner[0] === 'platform'
        ? await ja4BlocksApi.getAdmin(token, scopeID, id, requestID)
        : await ja4BlocksApi.getTenant(token, id, requestID)
      if (!activeRef.current || !currentToken(ownerKey)) return
      setWorkflow(result)
    } catch (error) {
      if (!activeRef.current || !currentToken(ownerKey)) return
      setReadError(error)
    } finally {
      if (activeRef.current && currentToken(ownerKey)) setReadPending(false)
    }
  }

  const executeCreate = async (nextAttempt: CreateAttempt) => {
    if (writePending) return
    const token = currentToken(ownerKey)
    if (!token) return
    setWritePending(true)
    setWriteError(null)
    setReadError(null)
    try {
      const receipt = nextAttempt.admin
        ? await ja4BlocksApi.createAdmin(token, nextAttempt.input as AdminJA4BlockCreateInput, nextAttempt.metadata)
        : await ja4BlocksApi.createTenant(token, nextAttempt.input as JA4BlockCreateInput, nextAttempt.metadata)
      if (!activeRef.current || !currentToken(ownerKey)) return
      setAttempt(null)
      setWorkflow(null)
      setWorkflowID(receipt.id)
      setWorkflowScopeID(nextAttempt.scopeID)
      await readWorkflow(receipt.id, nextAttempt.scopeID)
    } catch (error) {
      if (!activeRef.current || !currentToken(ownerKey)) return
      if (error instanceof ApiError && error.status === 403) setWriteForbidden(true)
      setWriteError(error)
      if (!outcomeUnknown(error)) setAttempt(null)
    } finally {
      if (activeRef.current && currentToken(ownerKey)) setWritePending(false)
    }
  }

  const submit = () => {
    const admin = owner[0] === 'platform'
    const scopeID = admin ? tenantScopeID : owner[2] ?? ''
    if (admin && !uuidPattern.test(scopeID)) { setFormError('validation.tenantScope'); return }
    if (!uuidPattern.test(siteID)) { setFormError('validation.site'); return }
    if (!ja4Pattern.test(ja4)) { setFormError('validation.ja4'); return }
    if (!Number.isFinite(Date.parse(snapshotAt))) { setFormError('validation.snapshot'); return }
    if (durationSeconds === null || durationSeconds < 60 || durationSeconds > 2_592_000) {
      setFormError('validation.duration')
      return
    }
    if (!reasonPattern.test(reason)) { setFormError('validation.reason'); return }
    if (!stepUp) { setFormError('validation.stepUp'); return }
    const tenantInput = Object.freeze({
      site_id: siteID,
      ja4,
      snapshot_at: snapshotAt,
      duration_seconds: durationSeconds,
      reason,
    })
    const input = admin ? Object.freeze({ ...tenantInput, tenant_scope_id: scopeID }) : tenantInput
    const nextAttempt = Object.freeze({
      admin,
      scopeID,
      input,
      metadata: Object.freeze(createJA4BlockWriteMetadata(stepUp)),
    })
    setAttempt(nextAttempt)
    setDialogOpen(false)
    setJA4('')
    setStepUp('')
    void executeCreate(nextAttempt)
  }

  const abandon = () => {
    setAttempt(null)
    setWriteError(null)
    setWorkflow(null)
    setWorkflowID('')
    setWorkflowScopeID('')
    setReadError(null)
    setReadPending(false)
  }

  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const activationConfirmed = workflow?.phase === 'active' && workflow.edge_state === 'active'
  const phaseLabel = workflow?.phase === 'active' && !activationConfirmed
    ? t('phases.edge_pending')
    : workflow ? t(`phases.${workflow.phase}`) : ''

  return (
    <section className="identity-page ja4-block-workflows-page">
      <header className="identity-page-header">
        <div>
          <Typography.Title level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        {!writeForbidden ? (
          <Button type="primary" icon={<Plus size={16} aria-hidden="true" />} onClick={openDialog}>
            {t('actions.create')}
          </Button>
        ) : null}
      </header>

      {uncertain ? (
        <OutcomeUnknown title={t('states.outcomeUnknown')} action={<Space wrap>
            <Button type="primary" loading={writePending} onClick={() => attempt && void executeCreate(attempt)}>
              {t('actions.retrySame')}
            </Button>
            <Button disabled={writePending} onClick={abandon}>{t('actions.abandon')}</Button>
          </Space>} />
      ) : writeError ? (
        <FeedbackWhen title={t(writeErrorKey(writeError))} />
      ) : null}

      {readPending ? (
        <DataState status="loading" message={t('states.loading')} />
      ) : readError ? (
        <FeedbackWhen title={t('states.loadError')} action={(
            <Button icon={<RefreshCw size={16} aria-hidden="true" />} onClick={() => workflowID && void readWorkflow(workflowID, workflowScopeID)}>
              {t('actions.retryRead')}
            </Button>
          )} />
      ) : workflow ? (
        <>
          <Space wrap className="identity-toolbar">
            <Typography.Title level={3}>{t('receipt.title')}</Typography.Title>
            <Tag color={activationConfirmed ? 'success' : 'processing'}>
              {activationConfirmed ? t('states.active') : phaseLabel}
            </Tag>
          </Space>
          <Alert type="info" showIcon message={t('receipt.disclaimer')} />
          <Descriptions size="small" bordered column={{ xs: 1, md: 2 }}>
            <Descriptions.Item label={t('fields.workflowId')}><Typography.Text copyable>{workflow.id}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('fields.ja4Sha256')}><Typography.Text copyable>{workflow.ja4_sha256}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('fields.revision')}>{workflow.revision}</Descriptions.Item>
            {workflow.policy_id ? <Descriptions.Item label={t('fields.policyId')}><Typography.Text copyable>{workflow.policy_id}</Typography.Text></Descriptions.Item> : null}
            {workflow.policy_revision ? <Descriptions.Item label={t('fields.policyRevision')}>{workflow.policy_revision}</Descriptions.Item> : null}
            {workflow.binding_id ? <Descriptions.Item label={t('fields.bindingId')}><Typography.Text copyable>{workflow.binding_id}</Typography.Text></Descriptions.Item> : null}
            {workflow.binding_revision ? <Descriptions.Item label={t('fields.bindingRevision')}>{workflow.binding_revision}</Descriptions.Item> : null}
            {workflow.edge_publication_id ? <Descriptions.Item label={t('fields.edgePublicationId')}><Typography.Text copyable>{workflow.edge_publication_id}</Typography.Text></Descriptions.Item> : null}
            <Descriptions.Item label={t('fields.rolloutId')}><Typography.Text copyable>{workflow.rollout_id}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('fields.edgeState')}>{t(`edgeStates.${workflow.edge_state || 'none'}`)}</Descriptions.Item>
            <Descriptions.Item label={t('fields.attemptCount')}>{workflow.attempt_count}</Descriptions.Item>
            <Descriptions.Item label={t('fields.snapshot')}>{workflow.snapshot_at}</Descriptions.Item>
            <Descriptions.Item label={t('fields.duration')}>{workflow.duration_seconds}</Descriptions.Item>
            {workflow.last_error_code ? <Descriptions.Item label={t('fields.lastError')}>{workflow.last_error_code}</Descriptions.Item> : null}
          </Descriptions>
        </>
      ) : (
        <DataState status="empty" message={t('states.empty')} />
      )}

      <Modal
        title={t('dialog.title')}
        open={dialogOpen}
        okText={t('actions.confirm')}
        cancelText={t('actions.cancel')}
        confirmLoading={writePending}
        onOk={submit}
        onCancel={() => { setDialogOpen(false); resetDraft() }}
      >
        <Form layout="vertical">
          {owner[0] === 'platform' ? (
            <Form.Item label={t('fields.tenantScopeId')}>
              <Input aria-label={t('fields.tenantScopeId')} value={tenantScopeID} onChange={(event) => setTenantScopeID(event.target.value)} />
            </Form.Item>
          ) : null}
          <Form.Item label={t('fields.siteId')}>
            <Input aria-label={t('fields.siteId')} value={siteID} onChange={(event) => setSiteID(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('fields.ja4')}>
            <Input aria-label={t('fields.ja4')} value={ja4} onChange={(event) => setJA4(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('fields.snapshotAt')}>
            <Input aria-label={t('fields.snapshotAt')} value={snapshotAt} onChange={(event) => setSnapshotAt(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('fields.durationSeconds')}>
            <InputNumber
              aria-label={t('fields.durationSeconds')}
              min={60}
              max={2_592_000}
              value={durationSeconds}
              onChange={setDurationSeconds}
            />
          </Form.Item>
          <Form.Item label={t('fields.reason')}>
            <Input aria-label={t('fields.reason')} value={reason} onChange={(event) => setReason(event.target.value)} />
          </Form.Item>
          <Form.Item label={t('fields.stepUp')}>
            <Input.Password aria-label={t('fields.stepUp')} value={stepUp} onChange={(event) => setStepUp(event.target.value)} />
          </Form.Item>
          {formError ? <Alert type="error" showIcon message={t(formError)} /> : null}
        </Form>
      </Modal>
    </section>
  )
}
