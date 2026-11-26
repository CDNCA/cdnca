import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Descriptions, Form, InputNumber, Select, Skeleton, Switch, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { newIdempotencyKey } from '../../api/market'
import {
  dnspupMonitorGroups, dnspupNodeIntervals, dnspupNodeMonitoringApi, estimateDNSPupNodeRequests, nodeProbeTypes,
  type DNSPupNodeMonitoringSettings, type DNSPupNodeMonitoringStatus, type ProbeDNSPupStatus,
} from '../../api/probeDNSPup'
import { SelectionFields, selectionOf, valuesOf, type SelectionValues } from './SelectionFields'
import { useProbeReason } from './probeErrors'
import '../../i18n/probeDNSPup'
import { useFeedback, FeedbackWhen, PageSection, useFormSubmitError } from '@cdnca/ui'

const queryKey = ['probe-dnspup-node-monitoring'] as const

type NodeForm = Omit<DNSPupNodeMonitoringSettings, 'selection'> & { selection: SelectionValues }

function formOf(status: DNSPupNodeMonitoringStatus): NodeForm {
  const { interval_seconds, groups, points_per_group, failure_percent, failure_rounds, recovery_rounds, low_balance } = status
  return { interval_seconds, groups, points_per_group, failure_percent, failure_rounds, recovery_rounds, low_balance,
    probe_type: status.probe_type ?? 'tcping', line_alert_min_points: status.line_alert_min_points ?? 3,
    line_alert_rounds: status.line_alert_rounds ?? 2, auto_diagnose: status.auto_diagnose ?? true,
    selection: valuesOf(status.selection) }
}

function settingsOf(values: NodeForm): DNSPupNodeMonitoringSettings {
  return { ...values, selection: selectionOf(values.selection ?? {}) }
}

// Node availability probing from dnspup checkpoints: the
// settings, the request estimate (dnspup meters one request per node IP and
// round, any checkpoint count) next to the dnspup balance.
// 停用提示只说当前真正成立的那一个原因（按连接设置的实际状态）。
export function inactiveReason(connection: ProbeDNSPupStatus): 'unlicensed' | 'disabled' | 'paused' | 'noKey' | 'unknown' {
  if (!connection.licensed) return 'unlicensed'
  if (!connection.enabled) return 'disabled'
  if (connection.paused_until) return 'paused'
  if (!connection.api_key || !connection.secret_configured) return 'noKey'
  return 'unknown'
}

export function NodeProbeCard({ token, connection }: { token: string; connection: ProbeDNSPupStatus }) {
  const { t, i18n } = useTranslation('probeDNSPup')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const [form] = Form.useForm<NodeForm>()
  const markSubmitError = useFormSubmitError(form)
  const status = useQuery({ queryKey, queryFn: () => dnspupNodeMonitoringApi.status(token), enabled: Boolean(token) })
  const interval = Form.useWatch('interval_seconds', form)
  const number = (value: number) => new Intl.NumberFormat(i18n.resolvedLanguage ?? i18n.language).format(value)
  const reason = useProbeReason()

  useEffect(() => {
    if (status.data) form.setFieldsValue(formOf(status.data))
  }, [status.data, form])

  const save = useMutation({
    mutationFn: async () => dnspupNodeMonitoringApi.save(token, settingsOf(await form.validateFields()), newIdempotencyKey('probe-dnspup-node')),
    onSuccess: (data) => { client.setQueryData(queryKey, data); void message.success(t('node.saved')) },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })

  if (status.error) return <PageSection title={t('node.title')}><FeedbackWhen title={reason(status.error)} /></PageSection>
  const data = status.data
  const addresses = data?.estimate.addresses ?? 0
  const estimate = estimateDNSPupNodeRequests({ interval_seconds: interval ?? data?.interval_seconds ?? 0 }, addresses)
  const remaining = data ? Math.max(data.monthly_limit - data.monthly_used, 0) : 0
  const balance = !data?.account_checked_at && !data?.monthly_limit ? t('node.balanceUnknown')
    : data.monthly_limit > 0 ? t('node.balanceValue', { remaining: number(remaining), limit: number(data.monthly_limit) })
      : t('node.balanceUnlimited', { used: number(data.monthly_used) })
  const intervalOptions = dnspupNodeIntervals.map((value) => ({ value,
    label: value === 0 ? t('node.intervals.off') : t('node.intervals.every', { minutes: value / 60 }) }))

  // estimate and balance side by side as one strip, every setting on the density grid
  // (numbers stay narrow), the selection fields join the same grid, save right under the last row.
  return <PageSection title={t('node.title')}>
    {status.isLoading ? <Skeleton active /> : <div className="probe-dnspup-section-body">
      <Typography.Paragraph type="secondary" className="probe-dnspup-section-intro">{t('node.intro')}</Typography.Paragraph>
      {data && !data.plugin_active ? <Alert type="warning" showIcon message={t('node.inactive', { reason: t(`node.inactiveReasons.${inactiveReason(connection)}`) })} /> : null}
      {data?.budget_state === 'low' ? <Alert type="warning" showIcon
        message={t('node.budgetLow', { minutes: data.effective_interval_seconds / 60 })} /> : null}
      {data?.budget_state === 'exhausted' ? <Alert type="error" showIcon message={t('node.budgetExhausted')} /> : null}
      <div>
        <Descriptions className="probe-dnspup-strip" column={{ xs: 1, md: 2 }} size="small" bordered>
          <Descriptions.Item label={t('node.estimate')}>
            <Typography.Text strong>{t('node.estimateValue', { day: number(estimate.perDay), month: number(estimate.perMonth) })}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label={t('node.balance')}>{balance}</Descriptions.Item>
        </Descriptions>
        <Typography.Text type="secondary" className="probe-dnspup-help">
          {t('node.estimateExtra', { addresses: number(addresses), points: number(data?.estimate.checkpoints_per_round ?? 0) })}
          {data && addresses > data.max_addresses_per_round ? ` ${t('node.rotate', { max: data.max_addresses_per_round })}` : ''}
        </Typography.Text>
      </div>
      <Form form={form} layout="vertical" disabled={!data} requiredMark={false}>
        <div className="density-form-grid probe-dnspup-form-grid">
          <Form.Item name="interval_seconds" label={t('node.interval')}>
            <Select options={intervalOptions} aria-label={t('node.interval')} />
          </Form.Item>
          <Form.Item name="probe_type" label={t('unified.node.probeType')}>
            <Select aria-label={t('unified.node.probeType')}
              options={nodeProbeTypes.map((value) => ({ value, label: t(`unified.node.probeTypes.${value}`) }))} />
          </Form.Item>
          <Form.Item name="low_balance" label={t('node.lowBalance')} extra={t('node.lowBalanceExtra')} rules={[{ required: true }]}>
            <InputNumber min={0} max={1_000_000_000} precision={0} aria-label={t('node.lowBalance')} />
          </Form.Item>
          <Form.Item className="density-span-all" name="groups" label={t('node.groups')} rules={[{ required: true, type: 'array', min: 1 }]}>
            <Checkbox.Group aria-label={t('node.groups')}
              options={dnspupMonitorGroups.map((value) => ({ value, label: t(`node.groupNames.${value}`) }))} />
          </Form.Item>
          <div className="density-span-all probe-dnspup-numbers">
          <Form.Item name="points_per_group" label={t('node.pointsPerGroup')} rules={[{ required: true }]}>
            <InputNumber min={1} max={20} precision={0} aria-label={t('node.pointsPerGroup')} />
          </Form.Item>
          <Form.Item name="failure_percent" label={t('node.failurePercent')} rules={[{ required: true }]}>
            <InputNumber min={1} max={99} precision={0} aria-label={t('node.failurePercent')} />
          </Form.Item>
          <Form.Item name="failure_rounds" label={t('node.failureRounds')} rules={[{ required: true }]}>
            <InputNumber min={1} max={10} precision={0} aria-label={t('node.failureRounds')} />
          </Form.Item>
          <Form.Item name="recovery_rounds" label={t('node.recoveryRounds')} rules={[{ required: true }]}>
            <InputNumber min={1} max={10} precision={0} aria-label={t('node.recoveryRounds')} />
          </Form.Item>
          </div>
          <SelectionFields form={form} prefix="selection" />
          <Typography.Text type="secondary" className="density-span-all probe-dnspup-help">{t('unified.node.lineAlertExtra')}</Typography.Text>
          <div className="density-span-all probe-dnspup-numbers">
          <Form.Item name="line_alert_min_points" label={t('unified.node.lineAlertMinPoints')} rules={[{ required: true }]}>
            <InputNumber min={1} max={20} precision={0} aria-label={t('unified.node.lineAlertMinPoints')} />
          </Form.Item>
          <Form.Item name="line_alert_rounds" label={t('unified.node.lineAlertRounds')} rules={[{ required: true }]}>
            <InputNumber min={1} max={10} precision={0} aria-label={t('unified.node.lineAlertRounds')} />
          </Form.Item>
          <Form.Item name="auto_diagnose" label={t('unified.node.autoDiagnose')} valuePropName="checked">
            <Switch aria-label={t('unified.node.autoDiagnose')} />
          </Form.Item>
          </div>
        </div>
        <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('node.save')}</Button>
      </Form>
    </div>}
  </PageSection>
}

