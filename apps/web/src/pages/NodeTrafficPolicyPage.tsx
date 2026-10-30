import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Divider,
  Form,
  Input,
  InputNumber,
  Result,
  Segmented,
  Select,
  Space,
  Spin,
  Typography,
} from 'antd'
import { useFeedbackMessage, FeedbackWhen } from '@cdnca/ui'
import { Plus, RefreshCw, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import { ApiError, type Principal } from '../api/auth'
import {
  nodeTrafficPoliciesApi,
  type NodeTrafficManualOverride,
  type NodeTrafficPolicyInput,
  type NodeTrafficScheduleWindow,
  type NodeTrafficWriteIdentity,
} from '../api/nodeTrafficPolicies'
import { useSessionStore } from '../auth/session'
import '../i18n/nodeTrafficPolicy'

type Owner = readonly [string, string, string, number]
type FormValues = {
  monthly_limit_bytes: number
  timezone: string
  override_mode: NodeTrafficManualOverride['mode']
  override_revision: number
  override_expires_at?: string
  windows: NodeTrafficScheduleWindow[]
}
type WriteAttempt = {
  expectedRevision: number
  input: NodeTrafficPolicyInput
  identity: NodeTrafficWriteIdentity
  ownerKey: string
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const timezonePattern = /^(?:UTC|[A-Za-z_+-]+\/[A-Za-z0-9_+./-]+)$/
const adminStateCodes = new Set(['pending', 'active', 'draining', 'disabled', 'retired'])
const evaluationReasonCodes = new Set([
  'within_policy', 'monthly_limit_reached', 'scheduled_window', 'manual_force_enabled',
  'manual_force_disabled', 'admin_state_protected', 'period_reset', 'policy_recovered',
])
const syncStatusCodes = new Set(['queued', 'running', 'succeeded', 'failed'])

function adminStateLabel(value: string, t: (key: string) => string): string {
  return t(adminStateCodes.has(value) ? `values.${value}` : 'values.unknown')
}

function evaluationReasonLabel(value: string, t: (key: string) => string): string {
  return t(evaluationReasonCodes.has(value) ? `reasons.${value}` : 'reasons.unknown')
}

function syncStatusLabel(value: string, t: (key: string) => string): string {
  return t(syncStatusCodes.has(value) ? `sync.${value}` : 'sync.unknown')
}

function hasPermission(principal: Principal, permission: string): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

function ownerFor(principal: Principal, sessionEpoch: number): Owner | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !uuidPattern.test(principal.scope_id) ||
    !uuidPattern.test(principal.user_id) || sessionEpoch < 1) return null
  return [principal.scope_kind, principal.scope_id, principal.user_id, sessionEpoch]
}

function currentToken(ownerKey: string, permission: string): string | null {
  const { principal, accessToken, sessionEpoch } = useSessionStore.getState()
  if (!principal || !accessToken || JSON.stringify(ownerFor(principal, sessionEpoch)) !== ownerKey || !hasPermission(principal, permission)) return null
  return accessToken
}

function requestIdentity(prefix: string): NodeTrafficWriteIdentity {
  const id = crypto.randomUUID()
  return { requestId: `${prefix}.${id}`, idempotencyKey: `${prefix}.${crypto.randomUUID()}` }
}

function unknownOutcome(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

export default function NodeTrafficPolicyPage() {
  const { t } = useTranslation('nodeTrafficPolicy')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  if (!principal || !accessToken) return null
  const owner = ownerFor(principal, sessionEpoch)
  if (!owner || !hasPermission(principal, 'nodes.read')) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  const ownerKey = JSON.stringify(owner)
  return <NodeTrafficPolicyContent key={ownerKey} ownerKey={ownerKey} canManage={hasPermission(principal, 'nodes.manage')} />
}

function NodeTrafficPolicyContent({ ownerKey, canManage }: { ownerKey: string; canManage: boolean }) {
  const { t } = useTranslation('nodeTrafficPolicy')
  const [params] = useSearchParams()
  const scopeId = params.get('scope_id') ?? ''
  const nodeId = params.get('node_id') ?? ''
  const validIdentity = uuidPattern.test(scopeId) && uuidPattern.test(nodeId)
  const [form] = Form.useForm<FormValues>()
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [advanced, setAdvanced] = useState(false)
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [evaluation, setEvaluation] = useState<Awaited<ReturnType<typeof nodeTrafficPoliciesApi.evaluate>> | null>(null)
  const policyKey = useMemo(() => ['node-traffic-policy', ownerKey, scopeId, nodeId] as const, [nodeId, ownerKey, scopeId])

  const policyQuery = useQuery({
    queryKey: policyKey,
    enabled: validIdentity,
    retry: false,
    refetchOnWindowFocus: false,
    queryFn: async () => {
      const token = currentToken(ownerKey, 'nodes.read')
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      const state = await nodeTrafficPoliciesApi.get(token, scopeId, nodeId)
      if (!currentToken(ownerKey, 'nodes.read')) throw new ApiError('Owner changed', 403, 'permission_denied')
      return state
    },
  })

  useEffect(() => {
    const policy = policyQuery.data?.policy
    if (!policy) return
    form.setFieldsValue({
      monthly_limit_bytes: policy.monthly_limit_bytes,
      timezone: policy.timezone,
      windows: policy.windows,
      override_mode: policy.manual_override.mode,
      override_revision: policy.manual_override.revision,
      override_expires_at: policy.manual_override.expires_at?.slice(0, 19),
    })
    setAdvanced(policy.windows.length > 0)
  }, [form, policyQuery.data])

  const saveMutation = useMutation({
    retry: false,
    mutationFn: async (value: WriteAttempt) => {
      const token = currentToken(value.ownerKey, 'nodes.manage')
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      return nodeTrafficPoliciesApi.put(token, scopeId, nodeId, value.expectedRevision, value.input, value.identity)
    },
    onSuccess: (state) => {
      setAttempt(null)
      setWriteError(null)
      queryClient.setQueryData(policyKey, state)
      messageApi.success(t('notices.saved'))
    },
    onError: (error, value) => {
      setWriteError(error)
      setAttempt(unknownOutcome(error) ? value : null)
    },
  })

  const evaluateMutation = useMutation({
    retry: false,
    mutationFn: async () => {
      const token = currentToken(ownerKey, 'nodes.manage')
      if (!token) throw new ApiError('Permission denied', 403, 'permission_denied')
      return nodeTrafficPoliciesApi.evaluate(token, scopeId, nodeId, requestIdentity('node-traffic-evaluate'))
    },
    onSuccess: (record) => {
      setEvaluation(record)
      messageApi.success(t('notices.evaluated'))
      void policyQuery.refetch()
    },
  })

  const syncTaskId = evaluation?.sync_task?.id ?? null
  const syncQuery = useQuery({
    queryKey: ['node-traffic-sync-task', ownerKey, syncTaskId],
    enabled: syncTaskId !== null,
    retry: false,
    queryFn: () => {
      const token = currentToken(ownerKey, 'nodes.read')
      if (!token || !syncTaskId) throw new ApiError('Permission denied', 403, 'permission_denied')
      return nodeTrafficPoliciesApi.getSyncTask(token, syncTaskId)
    },
    refetchInterval: (query) => ['queued', 'running'].includes(query.state.data?.status ?? '') ? 2_000 : false,
  })

  const overrideMode = Form.useWatch('override_mode', form) ?? 'none'

  const save = async () => {
    if (!policyQuery.data || !canManage || attempt) return
    const values = await form.validateFields()
    const expiry = values.override_mode === 'none' ? null : new Date(values.override_expires_at ?? '').toISOString()
    const currentOverride = policyQuery.data.policy.manual_override
    const changedOverride = values.override_mode !== currentOverride.mode || expiry !== currentOverride.expires_at
    const input: NodeTrafficPolicyInput = {
      monthly_limit_bytes: values.monthly_limit_bytes,
      timezone: values.timezone,
      windows: values.windows ?? [],
      manual_override: {
        mode: values.override_mode,
        revision: changedOverride ? currentOverride.revision + 1 : currentOverride.revision,
        expires_at: expiry,
      },
    }
    saveMutation.mutate({
      expectedRevision: policyQuery.data.policy.revision,
      input,
      identity: requestIdentity('node-traffic-policy'),
      ownerKey,
    })
  }

  if (!validIdentity) return <Result status="warning" title={t('validation.identity')} />
  if (policyQuery.isLoading) return <div className="route-loading" aria-label={t('loading')}><Spin size="small" /></div>
  if (policyQuery.error instanceof ApiError && policyQuery.error.status === 403) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  if (policyQuery.error || !policyQuery.data) {
    return <Result status="error" title={t('errors.load')} extra={<Button icon={<RefreshCw size={15} />} onClick={() => void policyQuery.refetch()}>{t('actions.retry')}</Button>} />
  }

  const adminState = policyQuery.data.admin_state
  const lastEvaluation = policyQuery.data.last_evaluation
  const syncTask = syncQuery.data ?? evaluation?.sync_task

  return (
    <section className="identity-page" data-testid="node-traffic-policy-page" style={{ minWidth: 0 }}>
      {messageContext}
      <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
        <div>
          <Typography.Title level={3}>{t('title')}</Typography.Title>
          <Typography.Text type="secondary">{t('description')}</Typography.Text>
        </div>
        <Alert
          type={adminState === 'active' ? 'success' : 'warning'}
          showIcon
          message={t('state.current', { state: adminStateLabel(adminState, t) })}
          description={lastEvaluation
            ? t('state.evaluation', { period: lastEvaluation.period_key, reason: evaluationReasonLabel(lastEvaluation.reason_code, t) })
            : t('state.noEvaluation')}
        />
        {writeError ? (
          <FeedbackWhen title={writeError instanceof ApiError && writeError.status === 403 ? t('errors.permissionDenied') : t('errors.write')} action={attempt ? <Button onClick={() => saveMutation.mutate(attempt)}>{t('actions.retry')}</Button> : undefined} />
        ) : null}
        {evaluateMutation.error ? <FeedbackWhen title={t('errors.evaluate')} /> : null}
        {policyQuery.data.policy.revision === 0 ? <Alert type="info" showIcon message={t('state.saveBeforeEvaluate')} /> : null}
        {syncTask ? <Alert type={syncTask.status === 'failed' ? 'error' : syncTask.status === 'succeeded' ? 'success' : 'info'} showIcon message={t('state.sync', { status: syncStatusLabel(syncTask.status, t) })} /> : null}

        <Form form={form} layout="vertical" requiredMark={false} initialValues={{ timezone: 'Asia/Shanghai', windows: [], override_mode: 'none', override_revision: 0 }}>
          <Form.Item
            name="monthly_limit_bytes"
            label={t('fields.monthlyLimit')}
            extra={t('values.unlimited')}
            rules={[{ required: true }, { validator: (_, value) => Number.isSafeInteger(value) && value >= 0 ? Promise.resolve() : Promise.reject(new Error(t('validation.monthlyLimit'))) }]}
          >
            <InputNumber min={0} precision={0} stringMode={false} style={{ width: '100%' }} disabled={!canManage || attempt !== null} />
          </Form.Item>
          <Form.Item name="timezone" label={t('fields.timezone')} rules={[{ required: true, pattern: timezonePattern, message: t('validation.timezone') }]}>
            <Input autoComplete="off" disabled={!canManage || attempt !== null} />
          </Form.Item>
          <Form.Item name="override_mode" label={t('fields.override')}>
            <Segmented
              disabled={!canManage || attempt !== null}
              options={[
                { label: t('values.none'), value: 'none' },
                { label: t('values.forceEnabled'), value: 'force_enabled' },
                { label: t('values.forceDisabled'), value: 'force_disabled' },
              ]}
            />
          </Form.Item>
          <Form.Item name="override_revision" hidden><InputNumber /></Form.Item>
          {overrideMode !== 'none' ? (
            <Form.Item
              name="override_expires_at"
              label={t('fields.overrideExpiry')}
              rules={[{ required: true, message: t('validation.overrideExpiry') }]}
            >
              <Input type="datetime-local" step={1} disabled={!canManage || attempt !== null} />
            </Form.Item>
          ) : null}

          <Button onClick={() => setAdvanced((value) => !value)}>{t('actions.advanced')}</Button>
          {advanced ? (
            <>
              <Divider />
              <Form.List name="windows">
                {(fields, { add, remove }) => (
                  <Space direction="vertical" style={{ width: '100%' }}>
                    {fields.map((field) => (
                      <Space key={field.key} wrap align="start">
                        <Form.Item name={[field.name, 'weekday']} label={t('fields.weekday')} rules={[{ required: true }]}>
                          <Select style={{ width: 120 }} options={[
                            'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday',
                          ].map((key, value) => ({ value, label: t(`values.weekdays.${key}`) }))} />
                        </Form.Item>
                        <Form.Item name={[field.name, 'start_minute']} label={t('fields.startMinute')} rules={[{ required: true }]}>
                          <InputNumber min={0} max={1439} precision={0} />
                        </Form.Item>
                        <Form.Item name={[field.name, 'end_minute']} label={t('fields.endMinute')} rules={[{ required: true }]}>
                          <InputNumber min={0} max={1439} precision={0} />
                        </Form.Item>
                        <Button aria-label={t('actions.removeWindow')} icon={<Trash2 size={15} />} onClick={() => remove(field.name)} />
                      </Space>
                    ))}
                    <Button icon={<Plus size={15} />} onClick={() => add({ weekday: 1, start_minute: 0, end_minute: 60 })}>{t('actions.addWindow')}</Button>
                  </Space>
                )}
              </Form.List>
            </>
          ) : null}
        </Form>

        <Space wrap>
          <Button type="primary" icon={<Save size={15} />} disabled={!canManage || attempt !== null} loading={saveMutation.isPending} onClick={() => void save()}>{t('actions.save')}</Button>
          <Button icon={<ShieldCheck size={15} />} disabled={!canManage || attempt !== null || policyQuery.data.policy.revision === 0} loading={evaluateMutation.isPending} onClick={() => evaluateMutation.mutate()}>{t('actions.evaluate')}</Button>
          <Button icon={<RefreshCw size={15} />} onClick={() => void policyQuery.refetch()}>{t('actions.refresh')}</Button>
        </Space>
      </Space>
    </section>
  )
}
