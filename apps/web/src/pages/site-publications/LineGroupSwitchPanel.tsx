import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Descriptions, Form, InputNumber, Modal, Select, Space, Tag } from 'antd'
import { ArrowRightLeft, RefreshCw } from 'lucide-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { ApiError, type Principal } from '../../api/auth'
import {
  createL4LineSwitch,
  getCurrentL4LineSwitch,
  newL4LineSwitchWriteMetadata,
  reconcileL4LineSwitch,
  type CreateL4LineSwitchInput,
  type L4LineSnapshotReference,
  type L4LineSwitch,
  type L4LineSwitchWriteMetadata,
} from '../../api/l4LineSwitches'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/sitePublications'
import { FeedbackWhen } from '@cdnca/ui'

export interface LineGroupSwitchOption {
  id: string
  label: string
}

interface LineGroupSwitchPanelProps {
  accessToken: string
  scopeID: string
  currentSourceRevision: number
  snapshots: LineGroupSwitchOption[]
  canManage: boolean
  loadSnapshot: (lineGroupID: string) => Promise<L4LineSnapshotReference>
  onChanged?: (value: L4LineSwitch) => void
}

interface SwitchFormValues {
  from_id: string
  to_id: string
  activation_timeout_ms: number
  observation_window_ms: number
  required_consecutive_successes: number
  health_timeout_ms: number
  max_drain_ms: number
  max_attempts: number
  deadline_minutes: number
}

const terminalStates = new Set(['completed', 'rolled_back', 'needs_attention'])

interface FrozenCommandBase {
  ownerKey: string
  accessToken: string
  scopeID: string
  metadata: L4LineSwitchWriteMetadata
}

interface FrozenCreateCommand extends FrozenCommandBase {
  kind: 'create'
  fromID: string
  toID: string
  expectedSourceRevision: number
  deadline: string
  values: Omit<SwitchFormValues, 'from_id' | 'to_id' | 'deadline_minutes'>
  body?: CreateL4LineSwitchInput
}

interface FrozenReconcileCommand extends FrozenCommandBase {
  kind: 'reconcile'
  switchID: string
}

type FrozenCommand = FrozenCreateCommand | FrozenReconcileCommand
type CommandHandle = Pick<FrozenCommandBase, 'ownerKey'> & { requestId: string }

function ownerKeyFor(principal: Principal | null, sessionEpoch: number, targetScopeID: string): string | null {
  if (!principal?.scope_id || !principal.user_id || !sessionEpoch || !targetScopeID) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id !== null) return null
  if (principal.scope_kind === 'tenant' && (
    !principal.tenant_id
  )) return null
  return JSON.stringify([
    principal.scope_kind,
    principal.scope_id,
    principal.tenant_id,
    principal.user_id,
    sessionEpoch,
    targetScopeID,
  ])
}

function canManageLineSwitch(principal: Principal | null): boolean {
  return principal?.scope_kind === 'platform' && (
    principal.permissions.includes('platform.admin') ||
    principal.permissions.includes('edge_publications.manage')
  )
}

function commandStillOwned(
  command: FrozenCommand,
  renderedAccessToken: string,
  renderedScopeID: string,
  canManage: boolean,
): boolean {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  return canManage && command.accessToken === renderedAccessToken && command.scopeID === renderedScopeID &&
    accessToken === command.accessToken && ownerKeyFor(principal, sessionEpoch, renderedScopeID) === command.ownerKey &&
    canManageLineSwitch(principal)
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

function writeErrorText(error: unknown, t: TFunction<'sitePublications'>): string {
  if (!(error instanceof ApiError)) return t('lineSwitch.errors.writeFailed')
  if (error.status === 403 || error.code === 'permission_denied') return t('lineSwitch.errors.forbidden')
  if (error.status === 404) return t('lineSwitch.errors.notFound')
  if (error.status === 409 || error.status === 412) return t('lineSwitch.errors.conflict')
  if (error.status === 400 || error.status === 422) return t('lineSwitch.errors.invalid')
  return t('lineSwitch.errors.writeFailed')
}

function readErrorText(error: unknown, t: TFunction<'sitePublications'>): string {
  return error instanceof ApiError && (error.status === 403 || error.code === 'permission_denied')
    ? t('lineSwitch.errors.readForbidden')
    : t('lineSwitch.errors.readFailed')
}

export default function LineGroupSwitchPanel({
  accessToken,
  scopeID,
  currentSourceRevision,
  snapshots,
  canManage,
  loadSnapshot,
  onChanged,
}: LineGroupSwitchPanelProps) {
  const { t, i18n } = useTranslation('sitePublications')
  const [form] = Form.useForm<SwitchFormValues>()
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState<L4LineSwitch | null>(null)
  const attemptRef = useRef<FrozenCommand | null>(null)
  const [attemptRequestID, setAttemptRequestID] = useState<string | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const sessionAccessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const ownerKey = useMemo(
    () => ownerKeyFor(principal, sessionEpoch, scopeID),
    [principal, scopeID, sessionEpoch],
  )
  const options = useMemo(() => snapshots.map((snapshot) => ({ value: snapshot.id, label: snapshot.label })), [snapshots])
  const currentQuery = useQuery({
    queryKey: ['l4-line-switch-current', ownerKey, scopeID],
    queryFn: () => getCurrentL4LineSwitch(accessToken, scopeID),
    enabled: Boolean(accessToken && scopeID && ownerKey && sessionAccessToken === accessToken),
    retry: false,
  })

  useEffect(() => {
    if (currentQuery.data !== undefined) setCurrent(currentQuery.data)
  }, [currentQuery.data])

  useEffect(() => setCurrent(null), [accessToken, ownerKey, scopeID])

  const clearAttempt = useCallback(() => {
    attemptRef.current = null
    setAttemptRequestID(null)
  }, [])

  const writeMutation = useMutation({
    mutationKey: ['l4-line-switch-command', scopeID],
    mutationFn: async (handle: CommandHandle): Promise<L4LineSwitch | null> => {
      let command = attemptRef.current
      if (!command || command.ownerKey !== handle.ownerKey || command.metadata.requestId !== handle.requestId ||
        !commandStillOwned(command, accessToken, scopeID, canManage)) {
        clearAttempt()
        return null
      }
      if (command.kind === 'reconcile') {
        return reconcileL4LineSwitch(command.accessToken, command.scopeID, command.switchID, command.metadata)
      }
      if (!command.body) {
        const [from, to] = await Promise.all([loadSnapshot(command.fromID), loadSnapshot(command.toID)])
        if (attemptRef.current !== command || !commandStillOwned(command, accessToken, scopeID, canManage)) {
          clearAttempt()
          return null
        }
        const body: CreateL4LineSwitchInput = {
          expected_source_revision: command.expectedSourceRevision,
          from: { ...from },
          to: { ...to },
          health: {
            activation_timeout_ms: command.values.activation_timeout_ms,
            observation_window_ms: command.values.observation_window_ms,
            required_consecutive_successes: command.values.required_consecutive_successes,
          },
          drain: {
            health_timeout_ms: command.values.health_timeout_ms,
            max_drain_ms: command.values.max_drain_ms,
          },
          max_attempts: command.values.max_attempts,
          deadline: command.deadline,
        }
        command = { ...command, body }
        attemptRef.current = command
      }
      if (!command.body) return null
      return createL4LineSwitch(command.accessToken, command.scopeID, command.body, command.metadata)
    },
    onSuccess: (value, handle) => {
      const command = attemptRef.current
      if (!value || !command || command.ownerKey !== handle.ownerKey ||
        command.metadata.requestId !== handle.requestId || !commandStillOwned(command, accessToken, scopeID, canManage)) return
      clearAttempt()
      setWriteError(null)
      setCurrent(value)
      setOpen(false)
      form.resetFields()
      onChanged?.(value)
    },
    onError: (error: unknown, handle) => {
      const command = attemptRef.current
      if (!command || command.ownerKey !== handle.ownerKey || command.metadata.requestId !== handle.requestId) return
      if (!commandStillOwned(command, accessToken, scopeID, canManage)) {
        clearAttempt()
        setWriteError(null)
        return
      }
      setOpen(false)
      setWriteError(error)
      const commandWasSent = command.kind === 'reconcile' || command.body !== undefined
      if (!commandWasSent || !outcomeUnknown(error)) clearAttempt()
    },
  })

  useEffect(() => {
    const command = attemptRef.current
    if (!command || commandStillOwned(command, accessToken, scopeID, canManage)) return
    clearAttempt()
    setWriteError(null)
    setOpen(false)
  }, [accessToken, canManage, clearAttempt, ownerKey, scopeID, sessionAccessToken])

  const activeAttempt = attemptRef.current?.metadata.requestId === attemptRequestID
    ? attemptRef.current
    : null
  const uncertain = Boolean(activeAttempt && writeError && outcomeUnknown(writeError))
  const writesLocked = writeMutation.isPending || uncertain

  const mutateCommand = (command: FrozenCommand) => {
    attemptRef.current = command
    setAttemptRequestID(command.metadata.requestId)
    setWriteError(null)
    writeMutation.mutate({ ownerKey: command.ownerKey, requestId: command.metadata.requestId })
  }

  const beginCreate = (values: SwitchFormValues) => {
    const currentOwnerKey = ownerKeyFor(
      useSessionStore.getState().principal,
      useSessionStore.getState().sessionEpoch,
      scopeID,
    )
    if (!canManage || !ownerKey || ownerKey !== currentOwnerKey || sessionAccessToken !== accessToken ||
      !canManageLineSwitch(useSessionStore.getState().principal) ||
      !snapshots.some((snapshot) => snapshot.id === values.from_id) ||
      !snapshots.some((snapshot) => snapshot.id === values.to_id) || values.from_id === values.to_id) return
    let metadata: L4LineSwitchWriteMetadata
    try {
      metadata = newL4LineSwitchWriteMetadata()
    } catch (error) {
      setOpen(false)
      setWriteError(error)
      return
    }
    mutateCommand({
      kind: 'create',
      ownerKey,
      accessToken,
      scopeID,
      metadata,
      fromID: values.from_id,
      toID: values.to_id,
      expectedSourceRevision: currentSourceRevision,
      deadline: new Date(Date.now() + values.deadline_minutes * 60_000).toISOString(),
      values: {
        activation_timeout_ms: values.activation_timeout_ms,
        observation_window_ms: values.observation_window_ms,
        required_consecutive_successes: values.required_consecutive_successes,
        health_timeout_ms: values.health_timeout_ms,
        max_drain_ms: values.max_drain_ms,
        max_attempts: values.max_attempts,
      },
    })
  }

  const beginReconcile = () => {
    if (!current || terminalStates.has(current.state) || !ownerKey || sessionAccessToken !== accessToken ||
      !canManage || !canManageLineSwitch(useSessionStore.getState().principal)) return
    let metadata: L4LineSwitchWriteMetadata
    try {
      metadata = newL4LineSwitchWriteMetadata()
    } catch (error) {
      setWriteError(error)
      return
    }
    mutateCommand({
      kind: 'reconcile',
      ownerKey,
      accessToken,
      scopeID,
      metadata,
      switchID: current.id,
    })
  }

  const retryExact = () => {
    if (!activeAttempt || !commandStillOwned(activeAttempt, accessToken, scopeID, canManage)) {
      clearAttempt()
      setWriteError(null)
      return
    }
    writeMutation.mutate({ ownerKey: activeAttempt.ownerKey, requestId: activeAttempt.metadata.requestId })
  }

  const abandonAndRefresh = async () => {
    if (!activeAttempt || !commandStillOwned(activeAttempt, accessToken, scopeID, canManage)) {
      clearAttempt()
      setWriteError(null)
      return
    }
    const result = await currentQuery.refetch()
    if (result.isError || attemptRef.current !== activeAttempt) return
    setCurrent(result.data ?? null)
    clearAttempt()
    setWriteError(null)
  }

  return (
    <section className="site-publications-line-switch" aria-labelledby="site-publications-line-switch-title">
      <div className="site-publications-toolbar">
        <div>
          <h2 id="site-publications-line-switch-title">{t('lineSwitch.title')}</h2>
          {current ? <Tag color={stateColor(current.state)}>{t(`lineSwitch.states.${current.state}`)}</Tag> : null}
        </div>
        {canManage ? (
          <Space wrap>
            {current && !terminalStates.has(current.state) ? (
              <Button
                icon={<RefreshCw size={15} />}
                loading={writeMutation.isPending && activeAttempt?.kind === 'reconcile'}
                disabled={writesLocked}
                onClick={beginReconcile}
              >
                {t('lineSwitch.actions.refresh')}
              </Button>
            ) : null}
            <Button type="primary" icon={<ArrowRightLeft size={15} />} disabled={snapshots.length < 2 || writesLocked} onClick={() => setOpen(true)}>
              {t('lineSwitch.actions.create')}
            </Button>
          </Space>
        ) : null}
      </div>

      {writeError && !uncertain ? (
        <FeedbackWhen title={writeErrorText(writeError, t)} detail={t('lineSwitch.errors.retry')} />
      ) : null}

      {currentQuery.error ? (
        <FeedbackWhen title={readErrorText(currentQuery.error, t)} detail={t('lineSwitch.errors.retry')} action={<Button size="small" loading={currentQuery.isFetching} onClick={() => void currentQuery.refetch()}>{t('lineSwitch.actions.retryRead')}</Button>} />
      ) : null}

      {current ? (
        <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
          <Descriptions.Item label={t('lineSwitch.fields.from')}>
            {t('lineSwitch.snapshot', { id: current.from.id, revision: current.from.revision })}
          </Descriptions.Item>
          <Descriptions.Item label={t('lineSwitch.fields.to')}>
            {t('lineSwitch.snapshot', { id: current.to.id, revision: current.to.revision })}
          </Descriptions.Item>
          <Descriptions.Item label={t('lineSwitch.fields.preparedNodes')}>{current.prepare_node_count}</Descriptions.Item>
          <Descriptions.Item label={t('lineSwitch.fields.retiringNodes')}>{current.retiring_node_count}</Descriptions.Item>
          <Descriptions.Item label={t('lineSwitch.fields.drainCommands')}>{current.drain_command_count}</Descriptions.Item>
          <Descriptions.Item label={t('lineSwitch.fields.updatedAt')}>
            {formatDateTime(current.updated_at, i18n.resolvedLanguage)}
          </Descriptions.Item>
          {current.state === 'health_gate' && current.dns_gate && current.dns_gate.state !== 'ready' ? (
            <Descriptions.Item label={t('lineSwitch.fields.dnsGate')} span={2}>
              {t(`lineSwitch.dnsGate.${current.dns_gate.state}`, {
                pending: current.dns_gate.pending_owners,
                owners: current.dns_gate.owners,
                readyAt: current.dns_gate.ready_at ? formatDateTime(current.dns_gate.ready_at, i18n.resolvedLanguage) : '',
              })}
            </Descriptions.Item>
          ) : null}
          {current.error_code ? (
            <Descriptions.Item label={t('lineSwitch.fields.errorCode')} span={2}>
              <code>{current.error_code}</code>
              {current.error_code === 'DNS_PROPAGATION_TIMEOUT' ? <> {t('lineSwitch.dnsGate.timeout')}</> : null}
            </Descriptions.Item>
          ) : null}
        </Descriptions>
      ) : (
        <div className="site-publications-empty">{t('lineSwitch.empty')}</div>
      )}

      <Modal
        open={open}
        title={t('lineSwitch.modal.title')}
        okText={t('lineSwitch.actions.confirm')}
        cancelText={t('actions.close')}
        confirmLoading={writeMutation.isPending && activeAttempt?.kind === 'create'}
        closable={!writeMutation.isPending}
        maskClosable={!writeMutation.isPending}
        keyboard={!writeMutation.isPending}
        cancelButtonProps={{ disabled: writeMutation.isPending }}
        okButtonProps={{ disabled: writesLocked }}
        destroyOnHidden
        onCancel={() => { if (!writeMutation.isPending) setOpen(false) }}
        onOk={() => void form.validateFields().then(beginCreate).catch(() => undefined)}
      >
        <Alert type="info" showIcon message={t('lineSwitch.modal.healthFirst')} />
        <Form<SwitchFormValues>
          form={form}
          layout="vertical"
          preserve={false}
          initialValues={{
            activation_timeout_ms: 60_000,
            observation_window_ms: 30_000,
            required_consecutive_successes: 3,
            health_timeout_ms: 30_000,
            max_drain_ms: 600_000,
            max_attempts: 3,
            deadline_minutes: 60,
          }}
        >
          <Form.Item name="from_id" label={t('lineSwitch.fields.from')} rules={[{ required: true }]}>
            <Select options={options} />
          </Form.Item>
          <Form.Item
            name="to_id"
            label={t('lineSwitch.fields.to')}
            dependencies={['from_id']}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator: (_, value) => value && value !== getFieldValue('from_id')
                  ? Promise.resolve()
                  : Promise.reject(new Error(t('lineSwitch.validation.distinctSnapshots'))),
              }),
            ]}
          >
            <Select options={options} />
          </Form.Item>
          <div className="site-publications-form-grid">
            <NumberField name="activation_timeout_ms" label={t('lineSwitch.fields.activationTimeout')} min={1} max={86_400_000} />
            <NumberField name="observation_window_ms" label={t('lineSwitch.fields.observationWindow')} min={1} max={86_400_000} />
            <NumberField name="required_consecutive_successes" label={t('lineSwitch.fields.successes')} min={1} max={100} />
            <NumberField name="health_timeout_ms" label={t('lineSwitch.fields.healthTimeout')} min={1} max={300_000} />
            <NumberField name="max_drain_ms" label={t('lineSwitch.fields.maxDrain')} min={1} max={86_400_000} />
            <NumberField name="max_attempts" label={t('lineSwitch.fields.maxAttempts')} min={1} max={10} />
            <NumberField name="deadline_minutes" label={t('lineSwitch.fields.deadlineMinutes')} min={1} max={1440} />
          </div>
        </Form>
      </Modal>

      <Modal
        open={uncertain}
        title={t('lineSwitch.unknown.title')}
        closable={false}
        maskClosable={false}
        keyboard={false}
        destroyOnHidden
        footer={[
          <Button key="abandon" disabled={writeMutation.isPending} onClick={() => void abandonAndRefresh()}>
            {t('lineSwitch.actions.abandonRefresh')}
          </Button>,
          <Button key="retry" type="primary" loading={writeMutation.isPending} onClick={retryExact}>
            {t('lineSwitch.actions.retryExact')}
          </Button>,
        ]}
      >
        <Alert type="warning" showIcon message={t('lineSwitch.unknown.title')} description={t('lineSwitch.unknown.description')} />
      </Modal>
    </section>
  )
}

function NumberField({ name, label, min, max }: { name: keyof SwitchFormValues; label: string; min: number; max: number }) {
  return (
    <Form.Item name={name} label={label} rules={[{ required: true, type: 'number', min, max }]}>
      <InputNumber min={min} max={max} precision={0} />
    </Form.Item>
  )
}

function stateColor(state: L4LineSwitch['state']): string {
  if (state === 'completed') return 'green'
  if (state === 'rolled_back') return 'gold'
  if (state === 'needs_attention') return 'red'
  return 'blue'
}
