import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Descriptions, Form, Input, InputNumber, Result, Select, Skeleton, Space, Switch, Tag, TimePicker, Typography } from 'antd'
import dayjs from 'dayjs'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { newIdempotencyKey } from '../../api/market'
import {
  ipIntelUpdatesApi, ipIntelUpdatesModule, type IPIntelLibrary, type IPIntelUpdateInput, type IPIntelUpdateStatus,
} from '../../api/ipIntelUpdates'
import { useSessionStore } from '../../auth/session'
import { PurchaseModuleLink } from '../../components/PurchaseModuleLink'
import '../../i18n/ipIntelUpdates'
import { useFeedback, FeedbackWhen, PageHeader, PageSection, useFormSubmitError } from '@cdnca/ui'
import './IPIntelUpdatesPage.css'

interface FormValues {
  enabled: boolean
  url: string
  api_key: string
  api_secret?: string
  interval_hours: number
  anchor: dayjs.Dayjs
  time_zone: string
}

const zones = ['Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore', 'Asia/Tokyo', 'UTC', 'Europe/London', 'America/Los_Angeles']

function toInput(values: FormValues, clearSecret: boolean): IPIntelUpdateInput {
  const input: IPIntelUpdateInput = {
    enabled: values.enabled, url: values.url.trim(), api_key: values.api_key.trim(),
    interval_minutes: Math.round(values.interval_hours * 60),
    anchor_minute: values.anchor.hour() * 60 + values.anchor.minute(), time_zone: values.time_zone,
  }
  const secret = values.api_secret?.trim()
  if (secret) input.api_secret = secret
  else if (clearSecret) input.api_secret = ''
  return input
}

function formatTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : '—'
}

export default function IPIntelUpdatesPage() {
  const { t } = useTranslation('ipIntelUpdates')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form] = Form.useForm<FormValues>()
  const markSubmitError = useFormSubmitError(form)
  const [clearSecret, setClearSecret] = useState(false)
  const status = useQuery({ queryKey: ['ip-intel-updates'], queryFn: () => ipIntelUpdatesApi.status(token), enabled: Boolean(token),
    refetchInterval: (query) => (query.state.data?.running || query.state.data?.check_requested ? 3000 : false) })
  const reason = (error: unknown) => t(`errors.${error instanceof ApiError ? error.code : 'request_failed'}`,
    { defaultValue: error instanceof ApiError ? error.code : t('errors.request_failed') })

  useEffect(() => {
    const data = status.data
    if (!data) return
    form.setFieldsValue({ enabled: data.enabled, url: data.url, api_key: data.api_key, api_secret: undefined,
      interval_hours: data.interval_minutes / 60, time_zone: data.time_zone,
      anchor: dayjs().hour(Math.floor(data.anchor_minute / 60)).minute(data.anchor_minute % 60).second(0) })
    setClearSecret(false)
  }, [status.data, form])

  const onSaved = (data: IPIntelUpdateStatus) => client.setQueryData(['ip-intel-updates'], data)
  const save = useMutation({
    mutationFn: async () => ipIntelUpdatesApi.save(token, toInput(await form.validateFields(), clearSecret), newIdempotencyKey('ipintel-save')),
    onSuccess: (data) => { onSaved(data); void message.success(t('form.saved')) },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })
  const test = useMutation({
    mutationFn: async () => ipIntelUpdatesApi.test(token, toInput(await form.validateFields(), false), newIdempotencyKey('ipintel-test')),
    onSuccess: (result) => {
      if (result.ok) void message.success(t('form.testOK', { release: result.release ?? '—' }))
      else void feedback.error(t('form.testFailed', { reason: t(`errors.${result.error_code}`, { defaultValue: result.error_code ?? '' }) }))
    },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })
  const check = useMutation({
    mutationFn: () => ipIntelUpdatesApi.check(token, newIdempotencyKey('ipintel-check')),
    onSuccess: (data) => { onSaved(data); void message.success(t('form.checkQueued')) },
    onError: (error) => { void feedback.error(reason(error)) },
  })

  if (status.error instanceof ApiError && status.error.status === 403) return <Result status="403" title={t('forbidden')} />
  if (status.error) return <FeedbackWhen title={reason(status.error)} />
  const data = status.data
  const licensed = Boolean(data?.licensed)

  const library = (value: IPIntelLibrary | null) => value ? <Space wrap>
    <Typography.Text type="secondary">{value.source_release}</Typography.Text>
    <Typography.Text type="secondary">{t('libraries.dataUpdated', { time: formatTime(value.data_updated_at) })}</Typography.Text>
    {!value.usable ? <Tag color="orange">{t('libraries.unusable')}</Tag> : null}
  </Space> : t('libraries.none')

  // Status first as two bordered description tables side by side (stacked below ~900px), then one
  // form section on the shared density grid; the enable switch sits in the action row next to 保存 because it only
  // takes effect when saved.
  return <PageSection className="ipintel-page">
    <PageHeader title={t('title')} description={t('intro')} />
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {data && !licensed ? <Alert type="warning" showIcon message={t('notLicensed')} action={<PurchaseModuleLink size="small" featureCode={ipIntelUpdatesModule} />} /> : null}
      {data ? <div className="ipintel-status">
        <Descriptions title={t('state.title')} bordered size="small" column={{ xs: 1, sm: 2, md: 2, lg: 2, xl: 2, xxl: 2 }}>
          <Descriptions.Item label={t('state.lastOutcome')}>
            <Space size={4} wrap>
              <Tag color={data.last_outcome === 'failed' ? 'red' : data.last_outcome === 'pending' ? 'orange' : undefined}>
                {t(`state.outcomes.${data.last_outcome}`)}</Tag>
              {data.last_http_status ? <Typography.Text type="secondary">HTTP {data.last_http_status}</Typography.Text> : null}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label={t('state.lastRelease')}>{data.last_release || '—'}</Descriptions.Item>
          <Descriptions.Item label={t('state.lastChecked')}>{formatTime(data.last_checked_at)}</Descriptions.Item>
          <Descriptions.Item label={t('state.lastSuccess')}>{formatTime(data.last_success_at)}</Descriptions.Item>
          <Descriptions.Item label={t('state.nextCheck')} span="filled">{data.enabled ? formatTime(data.next_check_at) : '—'}</Descriptions.Item>
          {data.last_error ? <Descriptions.Item label={t('state.lastError')} span="filled">
            <Typography.Text type="danger">{t(`errors.${data.last_error_code}`, { defaultValue: data.last_error_code })}: {data.last_error}</Typography.Text>
          </Descriptions.Item> : null}
        </Descriptions>
        <Descriptions title={t('libraries.title')} bordered size="small" column={1}>
          <Descriptions.Item label={t('libraries.nodeUses')}>
            {data.node_uses ? <Space size={4} wrap>
              <Tag color="blue">{data.node_uses === 'ipintel/local' ? t('libraries.local') : t('libraries.base')}</Tag>
              {data.use_reason ? <Typography.Text type="secondary">{t(`libraries.reasons.${data.use_reason}`)}</Typography.Text> : null}
            </Space> : t('libraries.none')}
          </Descriptions.Item>
          <Descriptions.Item label={t('libraries.base')}>{library(data.base)}</Descriptions.Item>
          <Descriptions.Item label={t('libraries.local')}>{library(data.local)}</Descriptions.Item>
        </Descriptions>
      </div> : null}
      <PageSection title={t('form.title')}>
        {status.isLoading ? <Skeleton active /> : <Form form={form} layout="vertical" disabled={!data} requiredMark={false}>
          <div className="density-form-grid">
            <Form.Item name="url" label={t('form.url')} rules={[{ required: true, type: 'url' }]}>
              <Input placeholder="https://api.dnspup.com/v1/tools/ip-intel-snapshot" autoComplete="off" />
            </Form.Item>
            <Form.Item name="api_key" label={t('form.apiKey')} rules={[{ required: true, min: 8 }]}>
              <Input autoComplete="off" />
            </Form.Item>
            <Form.Item name="api_secret" label={t('form.apiSecret')} rules={[{ min: 16 }]}
              extra={data?.secret_configured ? <Space size={[12, 0]} wrap>
                <span>{t('form.secretKeep', { fingerprint: data.secret_fingerprint })}</span>
                <Checkbox checked={clearSecret} onChange={(event) => setClearSecret(event.target.checked)}>{t('form.clearSecret')}</Checkbox>
              </Space> : t('form.secretUnset')}>
              <Input.Password autoComplete="new-password" />
            </Form.Item>
            <Form.Item name="interval_hours" label={t('form.interval')} rules={[{ required: true }]}>
              <InputNumber min={1} max={720} step={1} precision={0} />
            </Form.Item>
            <Form.Item name="anchor" label={t('form.anchor')} rules={[{ required: true }]}>
              <TimePicker format="HH:mm" minuteStep={5} allowClear={false} />
            </Form.Item>
            <Form.Item name="time_zone" label={t('form.timeZone')} rules={[{ required: true }]}>
              <Select options={zones.map((zone) => ({ value: zone, label: zone }))} />
            </Form.Item>
          </div>
          <div className="ipintel-actions">
            <span className="ipintel-enabled">
              <Form.Item name="enabled" valuePropName="checked" noStyle><Switch id="ipintel-enabled" disabled={!licensed} /></Form.Item>
              <label htmlFor="ipintel-enabled">{t('form.enabled')}</label>
            </span>
            <Space wrap>
              <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('form.save')}</Button>
              <Button loading={test.isPending} disabled={!licensed} onClick={() => test.mutate()}>{t('form.test')}</Button>
              <Button loading={check.isPending || data?.running} disabled={!licensed || !data?.enabled || data?.check_requested}
                onClick={() => check.mutate()}>{data?.running ? t('form.running') : t('form.checkNow')}</Button>
            </Space>
          </div>
        </Form>}
      </PageSection>
    </Space>
  </PageSection>
}
