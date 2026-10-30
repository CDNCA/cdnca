import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Drawer, Form, Input, Modal, Select, Space, Table, Tag, Tooltip, Typography,
  type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen } from '@cdnca/ui'
import { Play, Power, PowerOff, RefreshCw, ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { createMfaWriteMetadata, mfaApi, type MfaAuthenticationMethod } from '../../api/mfa'
import { paymentStepUpAction, pluginProvidersApi, type EnableConfirmation, type PluginProvider } from '../../api/pluginProviders'
import { useSessionStore } from '../../auth/session'
import '../../i18n/pluginProviders'
import { DataState } from '../../components/DataState'

const contractColor = { pending: 'default', passed: 'success', failed: 'error' } as const

interface ConfirmValues {
  risk: boolean
  method: MfaAuthenticationMethod
  code: string
}

// PaymentEnableDialog is the high-risk confirmation of a payment plugin
// (PA-23): the risk notice must be acknowledged, then an MFA step-up proof
// for the installation's tenant is issued and sent with the enable.
export function PaymentEnableDialog({ provider, busy, onCancel, onConfirm }: {
  provider: PluginProvider; busy: boolean; onCancel: () => void
  onConfirm: (confirmation: EnableConfirmation) => Promise<void>
}) {
  const { t } = useTranslation('pluginProviders')
  const accessToken = useSessionStore((state) => state.accessToken) ?? ''
  const [form] = Form.useForm<ConfirmValues>()
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const submit = async (values: ConfirmValues) => {
    if (!provider.tenant_id) {
      setError(t('hints.noTenant'))
      return
    }
    setVerifying(true)
    setError(null)
    try {
      const proof = await mfaApi.createStepUpProof(accessToken, {
        tenant_id: provider.tenant_id, audience: paymentStepUpAction, action: paymentStepUpAction,
        authentication: { method: values.method, code: values.code.trim() }, ttl_seconds: 300, max_uses: 1,
      }, createMfaWriteMetadata('step-up'))
      if (proof.replayed) throw new ApiError('Step-up replayed', 409, 'plugin_provider_step_up_required')
      await onConfirm({ risk_acknowledged: true, step_up_token: proof.token })
    } catch (cause) {
      const code = cause instanceof ApiError ? cause.code : ''
      setError(t(`errors.codes.${code}`, { defaultValue: '' }) || t('errors.codes.plugin_provider_step_up_required'))
    } finally {
      setVerifying(false)
    }
  }
  return <Modal open title={t('confirm.title', { id: provider.plugin_id })} onCancel={onCancel} footer={null} destroyOnHidden>
    <Typography.Paragraph>{t('confirm.intro')}</Typography.Paragraph>
    <Alert type="warning" showIcon icon={<ShieldAlert size={16} aria-hidden="true" />} style={{ marginBottom: 12 }}
      message={provider.risk_notice} />
    {error ? <Alert type="error" showIcon role="alert" style={{ marginBottom: 12 }} message={error} /> : null}
    <Form<ConfirmValues> form={form} layout="vertical" initialValues={{ risk: false, method: 'totp', code: '' }}
      onFinish={(values) => void submit(values)}>
      <Form.Item name="risk" valuePropName="checked"
        rules={[{ validator: (_, value) => (value ? Promise.resolve() : Promise.reject(new Error(t('confirm.needRisk')))) }]}>
        <Checkbox>{t('confirm.risk')}</Checkbox>
      </Form.Item>
      <Space wrap align="start">
        <Form.Item name="method" label={t('confirm.method')}>
          <Select style={{ width: 160 }} aria-label={t('confirm.method')}
            options={[{ value: 'totp', label: t('confirm.totp') }, { value: 'recovery_code', label: t('confirm.recovery') }]} />
        </Form.Item>
        <Form.Item name="code" label={t('confirm.code')} rules={[{ required: true, whitespace: true, message: t('confirm.needCode') }]}>
          <Input autoComplete="one-time-code" aria-label={t('confirm.code')} style={{ width: 220 }} />
        </Form.Item>
      </Space>
      <Space>
        <Button type="primary" danger htmlType="submit" loading={verifying || busy}>{t('confirm.submit')}</Button>
        <Button onClick={onCancel}>{t('confirm.cancel')}</Button>
      </Space>
    </Form>
  </Modal>
}

// 系统 > 第三方服务商插件 (PA-22/PA-23): DNS / SMS / ICP / payment plugins,
// their installation contract results, and enable / disable (enable only
// after the contract passed; a payment plugin also needs the high-risk
// confirmation).
export default function PluginProvidersPage() {
  const { t, i18n } = useTranslation('pluginProviders')
  const accessToken = useSessionStore((state) => state.accessToken) ?? ''
  const permissions = useSessionStore((state) => state.principal?.permissions) ?? []
  const canManage = permissions.includes('plugin_installations.manage') || permissions.includes('platform.admin')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [detail, setDetail] = useState<PluginProvider | null>(null)
  const [confirming, setConfirming] = useState<PluginProvider | null>(null)
  const queryKey = ['plugin-providers', accessToken]
  const list = useQuery({ queryKey, queryFn: () => pluginProvidersApi.list(accessToken), enabled: Boolean(accessToken), retry: false })
  const action = useMutation({
    mutationFn: ({ provider, kind, confirmation }: { provider: PluginProvider; kind: 'contract' | 'enable' | 'disable'
      confirmation?: EnableConfirmation }) =>
      pluginProvidersApi.action(accessToken, provider.plugin_id, kind, confirmation),
    onSuccess: (updated, { kind }) => {
      setConfirming(null)
      queryClient.setQueryData<PluginProvider[]>(queryKey, (items) =>
        items?.map((item) => item.plugin_id === updated.plugin_id ? updated : item))
      if (detail?.plugin_id === updated.plugin_id) setDetail(updated)
      messageApi.success(t(kind === 'contract' ? 'messages.ran' : kind === 'enable' ? 'messages.enabled' : 'messages.disabled'))
    },
    onError: (cause, { confirmation }) => {
      const code = cause instanceof ApiError ? cause.code : ''
      // The confirmation dialog shows its own error.
      if (!confirmation) feedback.error(t(`errors.codes.${code}`, { defaultValue: '' }) || t('errors.actionFailed'))
    },
  })
  const enable = (provider: PluginProvider) => provider.high_risk
    ? setConfirming(provider) : action.mutate({ provider, kind: 'enable' })
  const busy = (provider: PluginProvider, kind: string) =>
    action.isPending && action.variables?.provider.plugin_id === provider.plugin_id && action.variables.kind === kind
  const time = (value?: string) => value ? new Date(value).toLocaleString(i18n.language) : ''

  const columns: TableColumnsType<PluginProvider> = [
    { title: t('columns.plugin'), key: 'plugin', render: (_, provider) => <Space direction="vertical" size={0}>
      <Typography.Text strong>{provider.plugin_id}</Typography.Text>
      <Typography.Text type="secondary">v{provider.version} · {provider.base_url}</Typography.Text>
    </Space> },
    { title: t('columns.kinds'), key: 'kinds', render: (_, provider) => <Space size={4} wrap>
      {provider.kinds.map((kind) => <Tag key={kind}>{t(`kinds.${kind}`)}</Tag>)}
      {provider.high_risk ? <Tag color="red">{t('status.highRisk')}</Tag> : null}
    </Space> },
    { title: t('columns.contract'), key: 'contract', render: (_, provider) => {
      if (provider.status === 'withdrawn') return <Tag>{t('contract.withdrawn')}</Tag>
      const cases = provider.contract_report?.cases ?? []
      return <Space direction="vertical" size={0}>
        <Tag color={contractColor[provider.contract_status]}>{t(`contract.${provider.contract_status}`)}</Tag>
        {cases.length > 0 ? <Typography.Text type="secondary">
          {t('contract.cases', { passed: cases.filter((item) => item.passed).length, total: cases.length })}
        </Typography.Text> : null}
        {provider.contract_checked_at ? <Typography.Text type="secondary">
          {t('contract.checkedAt', { time: time(provider.contract_checked_at) })}</Typography.Text> : null}
      </Space>
    } },
    { title: t('columns.enabled'), key: 'enabled', render: (_, provider) => <Tag color={provider.usable ? 'success' : undefined}>
      {provider.usable ? t('status.usable') : provider.enabled ? t('status.enabled') : t('status.disabled')}</Tag> },
    { title: t('columns.actions'), key: 'actions', render: (_, provider) => {
      const active = provider.status === 'active'
      const passed = provider.contract_status === 'passed'
      return <Space wrap>
        <Button size="small" onClick={() => setDetail(provider)} disabled={!provider.contract_report}>{t('actions.details')}</Button>
        <Button size="small" icon={<Play size={14} />} disabled={!canManage || !active} loading={busy(provider, 'contract')}
          onClick={() => action.mutate({ provider, kind: 'contract' })}>{t('actions.run')}</Button>
        {provider.enabled
          ? <Button size="small" icon={<PowerOff size={14} />} disabled={!canManage} loading={busy(provider, 'disable')}
            onClick={() => action.mutate({ provider, kind: 'disable' })}>{t('actions.disable')}</Button>
          : <Tooltip title={passed ? undefined : t('hints.enableNeedsContract')}>
            <Button size="small" type="primary" icon={<Power size={14} />} disabled={!canManage || !active || !passed}
              loading={busy(provider, 'enable')} onClick={() => enable(provider)}>{t('actions.enable')}</Button>
          </Tooltip>}
      </Space>
    } },
  ]

  return <div className="page-shell">
    {messageContext}
    <Typography.Title level={4}>{t('title')}</Typography.Title>
    <Alert className="identity-alert density-note" type="info" showIcon message={t('intro')} />
    {list.isError ? <FeedbackWhen title={t('errors.loadFailed')} action={<Button size="small" onClick={() => void list.refetch()}>{t('actions.refresh')}</Button>} /> : null}
    <Table rowKey="plugin_id" columns={columns} dataSource={list.data ?? []} loading={list.isPending} pagination={false}
      locale={{ emptyText: list.isError ? <DataState status="error" message={t('errors.loadFailed')} onRetry={() => void list.refetch()} /> : t('hints.empty') }}
      title={() => <Button size="small" icon={<RefreshCw size={14} />} onClick={() => void list.refetch()}>{t('actions.refresh')}</Button>} />
    {confirming ? <PaymentEnableDialog provider={confirming} busy={action.isPending} onCancel={() => setConfirming(null)}
      onConfirm={(confirmation) => action.mutateAsync({ provider: confirming, kind: 'enable', confirmation }).then(() => undefined)} />
      : null}
    <Drawer open={detail !== null} width={520} onClose={() => setDetail(null)}
      title={detail ? t('detail.title', { id: detail.plugin_id }) : ''}>
      <Table size="small" rowKey={(item) => `${item.kind}/${item.id}`} pagination={false}
        dataSource={detail?.contract_report?.cases ?? []}
        columns={[
          { title: t('columns.kinds'), dataIndex: 'kind', render: (kind: PluginProvider['kinds'][number]) => t(`kinds.${kind}`) },
          { title: 'ID', dataIndex: 'id' },
          { title: t('columns.contract'), dataIndex: 'passed', render: (passed: boolean) =>
            <Tag color={passed ? 'success' : 'error'}>{passed ? t('detail.passed') : t('detail.failed')}</Tag> },
          { title: t('detail.code'), dataIndex: 'code' },
        ]} />
    </Drawer>
  </div>
}
