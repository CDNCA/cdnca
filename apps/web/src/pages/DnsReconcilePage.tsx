import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert, Button, Descriptions, Input, Popconfirm, Result, Select, Space, Table, Tag, Typography,
  type TableColumnsType,
} from 'antd'
import { Check, Play, RefreshCw, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate, useParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  dnsReconcileApi,
  type DNSReconcileCheckRequest,
  type DNSReconcileCommandIdentity,
  type DNSReconcileObservation,
  type DNSReconcileOperationResult,
  type DNSReconcileProviderOperation,
} from '../api/dnsReconcile'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import '../i18n/dnsReconcilePage'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import type { SiteDnsCheckContext } from './SiteDnsCheckPanel'

type Owner = readonly ['tenant', string, string, string, number]
type WriteKind = 'apply' | 'commit' | 'cancel'
type ApplyAttempt = { input: DNSReconcileCheckRequest; identity: DNSReconcileCommandIdentity }
type CommandAttempt = { kind: 'commit' | 'cancel'; identity: DNSReconcileCommandIdentity }

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const staleRead = new Error('stale DNS reconciliation read')
const unknownCodes = new Set(['dns_reconcile_result_unknown', 'network_error', 'request_timeout', 'dns_reconcile_request_timeout'])

function reconcileOwner(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'tenant' || !principal.tenant_id ||
    !principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  return ['tenant', principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function canRead(principal: Principal): boolean {
  return principal.scope_kind === 'tenant' && principal.permissions.includes('dns.read')
}

function canManage(principal: Principal): boolean {
  return principal.scope_kind === 'tenant' && principal.permissions.includes('dns.manage')
}

function currentAccess(ownerKey: string, permission: 'read' | 'manage'): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || (permission === 'read' ? !canRead(principal) : !canManage(principal))) return null
  const owner = reconcileOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.requestFailed'
  if (error.status === 403 || error.code === 'permission_denied' || error.code === 'dns_reconcile_entitlement_denied') return 'errors.forbidden'
  if (error.status === 404 || error.code === 'dns_reconcile_not_found') return 'errors.notFound'
  if (error.status === 409 || error.status === 412 || error.code === 'dns_reconcile_operation_in_flight' || error.code === 'dns_reconcile_commit_not_ready') return 'errors.conflict'
  if (error.status === 429) return 'errors.rateLimited'
  if (error.status === 503 || error.status === 504 || error.code === 'dns_reconcile_unavailable') return 'errors.unavailable'
  if (error.code === 'dns_reconcile_invalid_request' || error.status === 400) return 'errors.invalidRequest'
  return 'errors.requestFailed'
}

function isUnknown(error: unknown): boolean {
  return error instanceof ApiError ? unknownCodes.has(error.code) || [408, 429, 500, 502, 503, 504].includes(error.status) : true
}

function newIdentity(kind: WriteKind, revision?: number): DNSReconcileCommandIdentity {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const requestID = `dns-reconcile-${kind}-${suffix}`
  const traceID = `${'a'.repeat(31)}${(Date.now() % 16).toString(16)}`
  const spanID = `${'b'.repeat(15)}${(Date.now() % 16).toString(16)}`
  return {
    requestID,
    traceparent: `00-${traceID}-${spanID}-01`,
    idempotencyKey: `dns-reconcile-${kind}-${suffix}`,
    expectedRevision: revision ?? 1,
  }
}

// DC-UX-DETAIL-01（审测卡 12）：从解析检测进入时先给只读诊断（哪一层、哪个对象、什么原因、下一步），
// 不发写请求；高级修复计划在明确入口后，并带入被点的域名和 CNAME。
type Diagnosis = { layer: 'account' | 'cname' | 'provider' | 'propagation' | 'ok'; reason: string; next: 'configureDnsApi' | 'sync' | 'wait' | 'none' }

function diagnose(context: SiteDnsCheckContext): Diagnosis {
  if (!context.provider || !context.task) return { layer: 'account', reason: 'noAccount', next: 'configureDnsApi' }
  if (context.task.state === 'pending') return { layer: 'provider', reason: 'pending', next: 'wait' }
  const code = (context.task.code ?? '').replace(/^retries_exhausted:/u, '')
  if (context.resolve === 'done') return { layer: 'ok', reason: 'resolved', next: 'none' }
  if (code === 'cname_pending') return { layer: 'cname', reason: code, next: 'wait' }
  if (code === 'zone_not_hosted') return { layer: 'account', reason: code, next: 'configureDnsApi' }
  if (code === 'dns_record_unconfirmed') return { layer: 'propagation', reason: code, next: 'sync' }
  return { layer: 'provider', reason: code || 'unknown', next: 'sync' }
}

function DnsDiagnosis({ context }: { context: SiteDnsCheckContext }) {
  const { t } = useTranslation('dnsReconcilePage')
  const navigate = useNavigate()
  const diagnosis = diagnose(context)
  const back = () => navigate('/site/list', { state: { siteSubnav: 'dnsCheck', dnsCheckBack: context.back } })
  return (
    <section className="dns-reconcile-diagnosis" aria-labelledby="dns-diagnosis-title">
      <Typography.Title id="dns-diagnosis-title" level={3}>{t('diagnosis.title', { domain: context.domain })}</Typography.Title>
      <Alert type={diagnosis.layer === 'ok' ? 'success' : diagnosis.next === 'wait' ? 'info' : 'warning'} showIcon
        message={t(`diagnosis.layers.${diagnosis.layer}`)}
        description={t(`diagnosis.reasons.${diagnosis.reason}`, { defaultValue: t('diagnosis.reasons.unknown', { code: diagnosis.reason }) })} />
      <Descriptions bordered size="small" column={{ xs: 1, md: 2 }}>
        <Descriptions.Item label={t('diagnosis.domain')}>{context.domain}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.site')}>{context.siteDisplayID}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.cname')}>{context.cname || t('values.empty')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.account')}>{context.provider?.name ?? t('diagnosis.noAccount')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.task')}>{context.task
          ? t('diagnosis.taskState', { state: t(`diagnosis.taskStates.${context.task.state}`), attempts: context.task.attempts })
          : t('diagnosis.noTask')}</Descriptions.Item>
        <Descriptions.Item label={t('diagnosis.updatedAt')}>{context.task?.updatedAt ?? t('values.empty')}</Descriptions.Item>
      </Descriptions>
      <Space wrap>
        <Typography.Text>{t(`diagnosis.next.${diagnosis.next}`)}</Typography.Text>
        <Button onClick={back}>{t('diagnosis.back')}</Button>
      </Space>
    </section>
  )
}

function DnsReconcileContent({ owner, ownerKey, siteID, context }: {
  owner: Owner; ownerKey: string; siteID: string; context: SiteDnsCheckContext | null
}) {
  const { t } = useTranslation('dnsReconcilePage')
  const queryClient = useQueryClient()
  const fixedOwner = useRef(owner).current
  const prefix = useMemo(() => ['dns-reconcile', ...fixedOwner, siteID] as const, [fixedOwner, siteID])
  const lineageActive = useRef(true)
  // Without the check context (direct link) the expert form shows at once.
  const [advanced, setAdvanced] = useState(context === null)
  const [name, setName] = useState(context?.domain ?? '')
  const [expectedValue, setExpectedValue] = useState(context?.cname ?? '')
  const [authoritativeNS, setAuthoritativeNS] = useState('')
  const [ttl, setTtl] = useState('300')
  const [line, setLine] = useState('')
  const [weight, setWeight] = useState('0')
  const [propagationWindow, setPropagationWindow] = useState('900')
  const [zoneID, setZoneID] = useState('')
  const [providerRevision, setProviderRevision] = useState('1')
  const [recordType, setRecordType] = useState<'A' | 'AAAA' | 'CNAME'>(context?.cname ? 'CNAME' : 'A')
  const [formError, setFormError] = useState<string | null>(null)
  const [plan, setPlan] = useState<Awaited<ReturnType<typeof dnsReconcileApi.dryRun>> | null>(null)
  const [dryRunError, setDryRunError] = useState<unknown>(null)
  const [dryRunPending, setDryRunPending] = useState(false)
  const [taskID, setTaskID] = useState<string | null>(null)
  const [applyAttempt, setApplyAttempt] = useState<ApplyAttempt | null>(null)
  const [commandAttempt, setCommandAttempt] = useState<CommandAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [writePending, setWritePending] = useState(false)

  const guardedRead = useCallback(async () => {
    const token = lineageActive.current ? currentAccess(ownerKey, 'read') : null
    if (!token || !taskID) throw staleRead
    try {
      const value = await dnsReconcileApi.get(token, siteID, taskID, newIdentity('apply'))
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) throw staleRead
      return value
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) throw staleRead
      throw error
    }
  }, [ownerKey, siteID, taskID])

  const taskQuery = useQuery({
    queryKey: [...prefix, 'task', taskID ?? ''],
    enabled: Boolean(taskID), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false,
    queryFn: guardedRead,
  })

  useEffect(() => {
    lineageActive.current = true
    return () => {
      lineageActive.current = false
      void queryClient.cancelQueries({ queryKey: prefix })
      queryClient.removeQueries({ queryKey: prefix })
    }
  }, [prefix, queryClient])

  const inputFromForm = (): DNSReconcileCheckRequest | null => {
    const trimmedName = name.trim()
    const values = expectedValue.split(',').map((value) => value.trim()).filter(Boolean)
    const nameservers = authoritativeNS.split(',').map((value) => value.trim()).filter(Boolean)
    const ttlValue = Number(ttl)
    const lineValue = line.trim()
    const weightValue = Number(weight)
    const windowValue = Number(propagationWindow)
    const revision = Number(providerRevision)
    if (!trimmedName || !values.length || !zoneID.trim() || !Number.isSafeInteger(ttlValue) || ttlValue < 1 || ttlValue > 604800 ||
      line !== lineValue || new TextEncoder().encode(lineValue).length > 64 || [...lineValue].some((character) => {
        const codePoint = character.codePointAt(0) ?? 0
        return codePoint <= 0x1f || codePoint === 0x7f
      }) ||
      !Number.isSafeInteger(weightValue) || weightValue < 0 || weightValue > 100 ||
      !Number.isSafeInteger(windowValue) || windowValue < 1 || windowValue > 604800 || !Number.isSafeInteger(revision) || revision < 1) {
      setFormError(t('validation.required'))
      return null
    }
    setFormError(null)
    return {
      name: trimmedName,
      expected: [{ type: recordType, values }],
      authoritative_ns: nameservers,
      ttl: ttlValue,
      line: lineValue,
      weight: weightValue,
      propagation_window_seconds: windowValue,
      provider: { zone_id: zoneID.trim(), revision, records: [] },
    }
  }

  const doDryRun = async () => {
    if (dryRunPending) return
    const input = inputFromForm()
    const token = currentAccess(ownerKey, 'read')
    if (!input || !token) return
    setDryRunPending(true)
    setDryRunError(null)
    try {
      const value = await dnsReconcileApi.dryRun(token, siteID, input, newIdentity('apply'))
      if (!lineageActive.current || !currentAccess(ownerKey, 'read')) return
      setPlan(value)
    } catch (error) {
      if (lineageActive.current) setDryRunError(error)
    } finally {
      if (lineageActive.current) setDryRunPending(false)
    }
  }

  const executeApply = async (attempt: ApplyAttempt) => {
    const token = currentAccess(ownerKey, 'manage')
    if (!token || writePending) return
    setWritePending(true)
    setWriteError(null)
    try {
      const value = await dnsReconcileApi.apply(token, siteID, attempt.input, attempt.identity)
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setTaskID(value.id)
      setApplyAttempt(null)
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setWriteError(error)
      if (!isUnknown(error)) setApplyAttempt(null)
    } finally {
      if (lineageActive.current) setWritePending(false)
    }
  }

  const startApply = () => {
    if (!plan || applyAttempt || writePending) return
    const input = inputFromForm()
    const token = currentAccess(ownerKey, 'manage')
    if (!input || !token) return
    const attempt: ApplyAttempt = { input, identity: newIdentity('apply', plan.plan.precondition_revision) }
    setApplyAttempt(attempt)
    void executeApply(attempt)
  }

  const executeCommand = async (attempt: CommandAttempt) => {
    const token = currentAccess(ownerKey, 'manage')
    const currentTask = taskQuery.data
    if (!token || !currentTask || !taskID || writePending) return
    setWritePending(true)
    setWriteError(null)
    try {
      const value = attempt.kind === 'commit'
        ? await dnsReconcileApi.commit(token, siteID, taskID, attempt.identity)
        : await dnsReconcileApi.cancel(token, siteID, taskID, attempt.identity)
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      queryClient.setQueryData([...prefix, 'task', taskID], value)
      setCommandAttempt(null)
    } catch (error) {
      if (!lineageActive.current || !currentAccess(ownerKey, 'manage')) return
      setWriteError(error)
      if (!isUnknown(error)) setCommandAttempt(null)
    } finally {
      if (lineageActive.current) setWritePending(false)
    }
  }

  const startCommand = (kind: 'commit' | 'cancel') => {
    const currentTask = taskQuery.data
    const token = currentAccess(ownerKey, 'manage')
    if (!currentTask || !taskID || !token || commandAttempt || writePending) return
    const attempt: CommandAttempt = { kind, identity: newIdentity(kind, currentTask.revision) }
    setCommandAttempt(attempt)
    void executeCommand(attempt)
  }

  const abandonWrite = () => {
    setApplyAttempt(null)
    setCommandAttempt(null)
    setWriteError(null)
    setWritePending(false)
    void taskQuery.refetch()
  }

  const task = taskQuery.data
  const operationColumns: TableColumnsType<DNSReconcileProviderOperation> = [
    { title: t('columns.sequence'), dataIndex: 'sequence', width: 80 },
    { title: t('columns.action'), dataIndex: 'action', width: 100, render: (value: DNSReconcileProviderOperation['action']) => t(`operations.${value}`) },
    { title: t('columns.name'), dataIndex: 'name', width: 220 },
    { title: t('columns.type'), dataIndex: 'type', width: 80 },
    { title: t('columns.value'), dataIndex: 'value', width: 180 },
    {
      title: t('columns.line'), dataIndex: 'line', width: 140,
      render: (value?: string, operation?: DNSReconcileProviderOperation) => {
        const current = value || t('values.empty')
        return operation?.previous_line !== undefined && operation.previous_line !== value
          ? `${current} ← ${operation.previous_line || t('values.empty')}`
          : current
      },
    },
    {
      title: t('columns.weight'), dataIndex: 'weight', width: 120,
      render: (value?: number, operation?: DNSReconcileProviderOperation) => {
        const current = value ?? 0
        return operation?.previous_weight !== undefined && operation.previous_weight !== value
          ? `${current} ← ${operation.previous_weight}`
          : current
      },
    },
    { title: t('columns.reason'), dataIndex: 'reason', width: 180 },
  ]
  const resultColumns: TableColumnsType<DNSReconcileOperationResult> = [
    { title: t('columns.sequence'), dataIndex: 'source_sequence', width: 80 },
    { title: t('columns.action'), dataIndex: ['operation', 'action'], width: 100, render: (value: DNSReconcileProviderOperation['action']) => t(`operations.${value}`) },
    { title: t('columns.status'), dataIndex: 'status', width: 150, render: (value: string) => t(`operationStatuses.${value}`, { defaultValue: value }) },
    { title: t('columns.providerRequestID'), dataIndex: 'provider_request_id', width: 220, render: (value?: string) => value ? <Typography.Text copyable>{value}</Typography.Text> : t('values.empty') },
    { title: t('columns.providerRecordID'), dataIndex: 'provider_record_id', width: 220, render: (value?: string) => value ? <Typography.Text copyable>{value}</Typography.Text> : t('values.empty') },
    { title: t('columns.errorCode'), dataIndex: 'error_code', width: 180, render: (value: string) => value || t('values.empty') },
  ]
  const observationColumns: TableColumnsType<DNSReconcileObservation> = [
    { title: t('observations.role'), dataIndex: 'role', width: 150, render: (value: DNSReconcileObservation['role']) => t(`observations.roles.${value}`) },
    { title: t('observations.resolver'), dataIndex: 'resolver', width: 180 },
    { title: t('columns.type'), dataIndex: 'record_type', width: 80 },
    { title: t('columns.status'), dataIndex: 'status', width: 160 },
    { title: t('observations.values'), dataIndex: 'values', width: 220, render: (values: string[]) => values.join(', ') || t('values.empty') },
    { title: t('observations.minimumTTL'), dataIndex: 'minimum_ttl', width: 100 },
  ]
  const taskError = taskQuery.error
  const taskForbidden = taskError instanceof ApiError && taskError.status === 403
  const taskNotFound = taskError instanceof ApiError && taskError.status === 404
  const uncertain = Boolean(writeError && ((applyAttempt && isUnknown(writeError)) || (commandAttempt && isUnknown(writeError))))
  const manage = canManage(useSessionStore.getState().principal!)
  const status = task?.result.status
  const canCommit = Boolean(task && status === 'ready_to_commit' && manage)
  const canCancel = Boolean(task && !['committed', 'cancelled'].includes(status ?? '') && manage)

  return (
    <section className="identity-page dns-reconcile-page" aria-labelledby="dns-reconcile-title">
      <header className="identity-page-header">
        <div>
          <Typography.Title id="dns-reconcile-title" level={2}>{t('title')}</Typography.Title>
          <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
        </div>
        <Button icon={<RefreshCw size={16} aria-hidden="true" />} loading={taskQuery.isFetching} disabled={!taskID} onClick={() => void taskQuery.refetch()}>{t('actions.refreshTask')}</Button>
      </header>

      {context ? <DnsDiagnosis context={context} /> : null}
      {context && !advanced ? (
        <section className="dns-reconcile-advanced-entry" aria-label={t('advanced.title')}>
          <Typography.Paragraph type="secondary">{t('advanced.description')}</Typography.Paragraph>
          <Button onClick={() => setAdvanced(true)}>{t('advanced.open')}</Button>
        </section>
      ) : null}
      {advanced ? <>
      <div className="identity-toolbar">
        <Input aria-label={t('fields.name')} value={name} onChange={(event) => setName(event.target.value)} />
        <Select aria-label={t('fields.type')} value={recordType} options={['A', 'AAAA', 'CNAME'].map((value) => ({ value, label: value }))} onChange={setRecordType} />
        <Input aria-label={t('fields.expectedValue')} value={expectedValue} onChange={(event) => setExpectedValue(event.target.value)} />
        <Input aria-label={t('fields.authoritativeNS')} value={authoritativeNS} onChange={(event) => setAuthoritativeNS(event.target.value)} />
        <Input aria-label={t('fields.ttl')} value={ttl} onChange={(event) => setTtl(event.target.value)} />
        <Input aria-label={t('fields.line')} value={line} onChange={(event) => setLine(event.target.value)} />
        <Input aria-label={t('fields.weight')} value={weight} onChange={(event) => setWeight(event.target.value)} />
        <Input aria-label={t('fields.propagationWindow')} value={propagationWindow} onChange={(event) => setPropagationWindow(event.target.value)} />
        <Input aria-label={t('fields.zoneID')} value={zoneID} onChange={(event) => setZoneID(event.target.value)} />
        <Input aria-label={t('fields.providerRevision')} value={providerRevision} onChange={(event) => setProviderRevision(event.target.value)} />
        <Button icon={<Play size={15} aria-hidden="true" />} loading={dryRunPending} onClick={() => void doDryRun()}>{t('actions.generatePlan')}</Button>
      </div>
      {formError ? <div role="alert" className="data-state data-state-error">{formError}</div> : null}
      {dryRunPending ? <DataState status="loading" message={t('dryRun.loading')} /> : null}
      {dryRunError ? <DataState status="error" message={t(errorKey(dryRunError))} onRetry={() => void doDryRun()} /> : null}
      </> : null}

      {plan ? (
        <section aria-labelledby="dns-plan-title">
          <Typography.Title id="dns-plan-title" level={3}>{t('plan.title')}</Typography.Title>
          <Alert type={plan.plan.operations.length ? 'warning' : 'success'} showIcon message={t('plan.summary', { count: plan.plan.operations.length })} />
          <Descriptions bordered size="small" column={{ xs: 1, md: 3 }}>
            <Descriptions.Item label={t('plan.revision')}>{plan.plan.precondition_revision}</Descriptions.Item>
            <Descriptions.Item label={t('plan.digest')}><Typography.Text copyable>{plan.plan.digest}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label={t('plan.status')}><Tag>{t(`statuses.${plan.status}`)}</Tag></Descriptions.Item>
          </Descriptions>
          <Table rowKey="sequence" size="small" columns={operationColumns} dataSource={plan.plan.operations} pagination={false} locale={{ emptyText: t('plan.empty') }} scroll={{ x: 900 }} />
          {manage ? <Popconfirm title={t('confirmations.apply')} okText={t('actions.apply')} cancelText={t('actions.cancel')} onConfirm={startApply}><Button type="primary" icon={<Play size={15} aria-hidden="true" />} disabled={writePending || Boolean(applyAttempt)}>{t('actions.apply')}</Button></Popconfirm> : null}
        </section>
      ) : null}

      {uncertain ? (
        <OutcomeUnknown title={t('unknown.title')} detail={t('unknown.description')} action={<Space wrap>
          <Button type="primary" loading={writePending} onClick={() => applyAttempt ? void executeApply(applyAttempt) : commandAttempt ? void executeCommand(commandAttempt) : undefined}>{t('actions.retrySameRequest')}</Button>
          <Button disabled={writePending} onClick={abandonWrite}>{t('actions.abandonRefresh')}</Button>
        </Space>} />
      ) : writeError ? <DataState status="error" message={t(errorKey(writeError))} onRetry={abandonWrite} /> : null}

      {taskID ? (
        <section aria-labelledby="dns-task-title">
          <Typography.Title id="dns-task-title" level={3}>{t('task.title')}</Typography.Title>
          {taskQuery.isPending ? <DataState status="loading" message={t('task.loading')} /> : taskForbidden ? <DataState status="forbidden" message={t('errors.forbiddenTitle')} description={t('errors.forbiddenDescription')} /> : taskNotFound ? <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} /> : taskQuery.isError ? <DataState status="error" message={t(errorKey(taskError))} onRetry={() => void taskQuery.refetch()} /> : task ? (
            <>
              <Space wrap>
                <Tag color={status === 'committed' ? 'success' : status === 'failed' || status === 'commit_failed' ? 'error' : 'processing'}>{t(`statuses.${status}`)}</Tag>
                <Typography.Text>{t('task.revision', { revision: task.revision })}</Typography.Text>
                <Typography.Text>{t('task.progress', task.job.progress)}</Typography.Text>
              </Space>
              <Descriptions bordered size="small" column={{ xs: 1, md: 3 }}>
                <Descriptions.Item label={t('task.id')}><Typography.Text copyable>{task.id}</Typography.Text></Descriptions.Item>
                <Descriptions.Item label={t('task.jobAttempt')}>{t('task.attempt', { attempt: task.job.attempt, maximum: task.job.max_attempts })}</Descriptions.Item>
                <Descriptions.Item label={t('task.providerRevision')}>{task.result.provider_revision}</Descriptions.Item>
              </Descriptions>
              {task.result.error_code ? <FeedbackWhen title={t('task.failure', { code: task.result.error_code })} /> : null}
              <div aria-busy={taskQuery.isFetching}>
                <Typography.Title level={4}>{t('operationResults.title')}</Typography.Title>
                {task.result.operations.length === 0 ? <DataState status="empty" message={t('operationResults.empty')} /> : <Table
                  rowKey="client_request_id" size="small" pagination={false} scroll={{ x: 950 }}
                  dataSource={task.result.operations} columns={resultColumns}
                />}
              </div>
              <div aria-busy={taskQuery.isFetching}>
                <Typography.Title level={4}>{t('propagation.title')}</Typography.Title>
                {task.result.propagation.length === 0 ? <DataState status="empty" message={t('propagation.empty')} /> : <Table rowKey="number" size="small" pagination={false} dataSource={task.result.propagation} columns={[
                  { title: t('propagation.attempt'), dataIndex: 'number' },
                  { title: t('propagation.status'), dataIndex: 'status', render: (value: string) => t(`propagation.states.${value}`, { defaultValue: value }) },
                  { title: t('propagation.healthy'), dataIndex: 'consecutive_healthy' },
                ]} />}
              </div>
              {task.result.last_check ? (
                <div>
                  <Typography.Title level={4}>{t('observations.title')}</Typography.Title>
                  {task.result.status === 'failed' || task.result.status === 'commit_failed' || task.result.status === 'timed_out'
                    ? <FeedbackWhen type="warning" title={t('observations.lkg')} />
                    : null}
                  <Table rowKey={(item) => `${item.role}:${item.resolver}:${item.record_type}`} size="small" pagination={false}
                    scroll={{ x: 900 }} dataSource={task.result.last_check.observations} columns={observationColumns} />
                </div>
              ) : null}
              {task.result.compensation_plan.length ? (
                <div>
                  <Typography.Title level={4}>{t('compensation.title')}</Typography.Title>
                  <Table rowKey="sequence" size="small" columns={operationColumns} dataSource={task.result.compensation_plan}
                    pagination={false} scroll={{ x: 900 }} />
                </div>
              ) : null}
              <Space wrap>
                {canCommit ? <Popconfirm title={t('confirmations.commit')} okText={t('actions.commit')} cancelText={t('actions.cancel')} onConfirm={() => startCommand('commit')}><Button type="primary" icon={<Check size={15} aria-hidden="true" />} disabled={writePending || Boolean(commandAttempt)}>{t('actions.commit')}</Button></Popconfirm> : null}
                {canCancel ? <Popconfirm title={t('confirmations.cancel')} okText={t('actions.cancelTask')} cancelText={t('actions.keep')} onConfirm={() => startCommand('cancel')}><Button danger icon={<X size={15} aria-hidden="true" />} disabled={writePending || Boolean(commandAttempt)}>{t('actions.cancelTask')}</Button></Popconfirm> : null}
              </Space>
            </>
          ) : null}
        </section>
      ) : advanced ? <DataState status="empty" message={t('task.prompt')} /> : null}
    </section>
  )
}

export default function DnsReconcilePage() {
  const { t } = useTranslation('dnsReconcilePage')
  const { id = '' } = useParams()
  const routeState = useLocation().state as { dnsCheck?: SiteDnsCheckContext } | null
  const context = routeState?.dnsCheck?.siteID === id ? routeState.dnsCheck : null
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? reconcileOwner(principal, sessionEpoch) : null
  if (!accessToken || !principal) return null
  if (!uuidPattern.test(id)) return <Result status="404" title={t('errors.notFoundTitle')} subTitle={t('errors.notFoundDescription')} />
  if (!owner || !canRead(principal)) return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  const ownerKey = JSON.stringify(owner)
  return <DnsReconcileContent key={ownerKey} owner={owner} ownerKey={ownerKey} siteID={id} context={context} />
}
