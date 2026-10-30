import { useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Checkbox, Descriptions, Form, InputNumber, Select, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { newIdempotencyKey } from '../../api/market'
import {
  dnspupMonitorGroups, dnspupNodeIntervals, dnspupNodeMonitoringApi, estimateDNSPupNodeRequests,
  type DNSPupNodeMonitoringSettings, type DNSPupNodeMonitoringStatus,
} from '../../api/probeDNSPup'
import '../../i18n/probeDNSPup'
import { useFeedback, FeedbackWhen, useFormSubmitError } from '@cdnca/ui'

const queryKey = ['probe-dnspup-node-monitoring'] as const

function settingsOf(status: DNSPupNodeMonitoringStatus): DNSPupNodeMonitoringSettings {
  const { interval_seconds, groups, points_per_group, failure_percent, failure_rounds, recovery_rounds, low_balance } = status
  return { interval_seconds, groups, points_per_group, failure_percent, failure_rounds, recovery_rounds, low_balance }
}

// Node availability probing from dnspup checkpoints: the
// settings, the request estimate (dnspup meters one request per node IP and
// round, any checkpoint count) next to the dnspup balance.
export function NodeProbeCard({ token }: { token: string }) {
  const { t, i18n } = useTranslation('probeDNSPup')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const client = useQueryClient()
  const [form] = Form.useForm<DNSPupNodeMonitoringSettings>()
  const markSubmitError = useFormSubmitError(form)
  const status = useQuery({ queryKey, queryFn: () => dnspupNodeMonitoringApi.status(token), enabled: Boolean(token) })
  const interval = Form.useWatch('interval_seconds', form)
  const number = (value: number) => new Intl.NumberFormat(i18n.resolvedLanguage ?? i18n.language).format(value)
  const reason = (error: unknown) => error instanceof ApiError && i18n.exists(`probeDNSPup:errors.${error.code}`)
    ? t(`errors.${error.code}`) : t('errors.request_failed')

  useEffect(() => {
    if (status.data) form.setFieldsValue(settingsOf(status.data))
  }, [status.data, form])

  const save = useMutation({
    mutationFn: async () => dnspupNodeMonitoringApi.save(token, await form.validateFields(), newIdempotencyKey('probe-dnspup-node')),
    onSuccess: (data) => { client.setQueryData(queryKey, data); void message.success(t('node.saved')) },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })

  if (status.error) return <Card title={t('node.title')}><FeedbackWhen title={reason(status.error)} /></Card>
  const data = status.data
  const addresses = data?.estimate.addresses ?? 0
  const estimate = estimateDNSPupNodeRequests({ interval_seconds: interval ?? data?.interval_seconds ?? 0 }, addresses)
  const remaining = data ? Math.max(data.monthly_limit - data.monthly_used, 0) : 0
  const balance = !data?.account_checked_at && !data?.monthly_limit ? t('node.balanceUnknown')
    : data.monthly_limit > 0 ? t('node.balanceValue', { remaining: number(remaining), limit: number(data.monthly_limit) })
      : t('node.balanceUnlimited', { used: number(data.monthly_used) })
  const intervalOptions = dnspupNodeIntervals.map((value) => ({ value,
    label: value === 0 ? t('node.intervals.off') : t('node.intervals.every', { minutes: value / 60 }) }))

  return <Card title={t('node.title')} loading={status.isLoading}>
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Typography.Paragraph type="secondary">{t('node.intro')}</Typography.Paragraph>
      {data && !data.plugin_active ? <Alert type="warning" showIcon message={t('node.inactive')} /> : null}
      {data?.budget_state === 'low' ? <Alert type="warning" showIcon
        message={t('node.budgetLow', { minutes: data.effective_interval_seconds / 60 })} /> : null}
      {data?.budget_state === 'exhausted' ? <Alert type="error" showIcon message={t('node.budgetExhausted')} /> : null}
      <Descriptions column={1} size="small" bordered>
        <Descriptions.Item label={t('node.estimate')}>
          <Typography.Text strong>{t('node.estimateValue', { day: number(estimate.perDay), month: number(estimate.perMonth) })}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label={t('node.balance')}>{balance}</Descriptions.Item>
      </Descriptions>
      <Typography.Text type="secondary">
        {t('node.estimateExtra', { addresses: number(addresses), points: number(data?.estimate.checkpoints_per_round ?? 0) })}
        {data && addresses > data.max_addresses_per_round ? ` ${t('node.rotate', { max: data.max_addresses_per_round })}` : ''}
      </Typography.Text>
      <Form form={form} layout="vertical" disabled={!data} requiredMark={false}>
        <Form.Item name="interval_seconds" label={t('node.interval')}>
          <Select options={intervalOptions} aria-label={t('node.interval')} />
        </Form.Item>
        <Form.Item name="groups" label={t('node.groups')} rules={[{ required: true, type: 'array', min: 1 }]}>
          <Checkbox.Group aria-label={t('node.groups')}
            options={dnspupMonitorGroups.map((value) => ({ value, label: t(`node.groupNames.${value}`) }))} />
        </Form.Item>
        <Space wrap size="large">
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
        </Space>
        <Form.Item name="low_balance" label={t('node.lowBalance')} extra={t('node.lowBalanceExtra')} rules={[{ required: true }]}>
          <InputNumber min={0} max={1_000_000_000} precision={0} aria-label={t('node.lowBalance')} />
        </Form.Item>
        <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('node.save')}</Button>
      </Form>
    </Space>
  </Card>
}
