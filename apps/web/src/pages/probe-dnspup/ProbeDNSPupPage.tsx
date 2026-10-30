import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Card, Descriptions, Form, Input, Result, Select, Space, Switch, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { newIdempotencyKey } from '../../api/market'
import {
  probeDNSPupApi, probeDNSPupModule, type EdgeProbeSource, type OriginProbeSource, type ProbeDNSPupInput,
  type ProbeDNSPupStatus,
} from '../../api/probeDNSPup'
import { useSessionStore } from '../../auth/session'
import { PurchaseModuleLink } from '../../components/PurchaseModuleLink'
import '../../i18n/probeDNSPup'
import { NodeProbeCard } from './NodeProbeCard'
import { useFeedback, FeedbackWhen, useFormSubmitError } from '@cdnca/ui'

interface FormValues {
  enabled: boolean
  base_url: string
  api_key: string
  api_secret?: string
  source_domain: string
  origin_sources: OriginProbeSource[]
  edge_sources: EdgeProbeSource[]
}

const originSources: OriginProbeSource[] = ['node', 'dnspup', 'controller']
const edgeSources: EdgeProbeSource[] = ['node', 'dnspup']

function toInput(values: FormValues, clearSecret: boolean): ProbeDNSPupInput {
  const input: ProbeDNSPupInput = {
    enabled: values.enabled, base_url: values.base_url.trim(), api_key: values.api_key.trim(),
    source_domain: values.source_domain?.trim() ?? '', origin_sources: values.origin_sources, edge_sources: values.edge_sources,
  }
  const secret = values.api_secret?.trim()
  if (secret) input.api_secret = secret
  else if (clearSecret) input.api_secret = ''
  return input
}

function formatTime(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : '—'
}

export default function ProbeDNSPupPage() {
  const { t } = useTranslation('probeDNSPup')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [form] = Form.useForm<FormValues>()
  const markSubmitError = useFormSubmitError(form)
  const [clearSecret, setClearSecret] = useState(false)
  const status = useQuery({ queryKey: ['probe-dnspup'], queryFn: () => probeDNSPupApi.status(token), enabled: Boolean(token) })
  const reason = (error: unknown) => t(`errors.${error instanceof ApiError ? error.code : 'request_failed'}`,
    { defaultValue: error instanceof ApiError ? error.code : t('errors.request_failed') })

  useEffect(() => {
    const data = status.data
    if (!data) return
    form.setFieldsValue({ enabled: data.enabled, base_url: data.base_url, api_key: data.api_key, api_secret: undefined,
      source_domain: data.source_domain, origin_sources: data.origin_sources, edge_sources: data.edge_sources })
    setClearSecret(false)
  }, [status.data, form])

  const save = useMutation({
    mutationFn: async () => probeDNSPupApi.save(token, toInput(await form.validateFields(), clearSecret), newIdempotencyKey('probe-dnspup-save')),
    onSuccess: (data: ProbeDNSPupStatus) => { client.setQueryData(['probe-dnspup'], data); void message.success(t('form.saved')) },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })
  const test = useMutation({
    mutationFn: async () => probeDNSPupApi.test(token, toInput(await form.validateFields(), false), newIdempotencyKey('probe-dnspup-test')),
    onSuccess: (result) => {
      void client.invalidateQueries({ queryKey: ['probe-dnspup'] })
      if (result.ok) void message.success(t('form.testOK', { used: result.monthly_used, limit: result.monthly_limit }))
      else void feedback.error(t('form.testFailed', { reason: t(`errors.${result.error_code}`, { defaultValue: result.error_code ?? '' }) }))
    },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })

  if (status.error instanceof ApiError && status.error.status === 403) return <Result status="403" title={t('forbidden')} />
  if (status.error) return <FeedbackWhen title={reason(status.error)} />
  const data = status.data
  const licensed = Boolean(data?.licensed)
  const sourceOptions = (values: string[]) => values.map((value) => ({ value, label: t(`sources.${value}`) }))

  return <Space direction="vertical" size="large" style={{ width: '100%' }}>
    <Typography.Title level={3}>{t('title')}</Typography.Title>
    <Typography.Paragraph type="secondary" className="density-note">{t('intro')}</Typography.Paragraph>
    {data && !licensed ? <Alert type="warning" showIcon message={t('notLicensed')} action={<PurchaseModuleLink size="small" featureCode={probeDNSPupModule} />} /> : null}
    {data?.paused_until ? <Alert type="error" showIcon message={`${t('state.pausedUntil')} ${formatTime(data.paused_until)}`}
      description={`${t(`state.reasons.${data.pause_reason}`, { defaultValue: data.pause_reason })} (${data.pause_code})`} /> : null}
    <Alert className="density-note" type="info" showIcon message={t('limits')} />
    <Card loading={status.isLoading}>
      <Form form={form} layout="vertical" disabled={!data} requiredMark={false}>
        <div className="density-form-grid">
        <Form.Item className="density-span-all" name="enabled" label={t('form.enabled')} valuePropName="checked">
          <Switch disabled={!licensed} />
        </Form.Item>
        <Form.Item name="base_url" label={t('form.baseURL')} rules={[{ required: true, type: 'url' }]}>
          <Input placeholder="https://api.dnspup.com" autoComplete="off" />
        </Form.Item>
        <Form.Item name="api_key" label={t('form.apiKey')} rules={[{ required: true, min: 8 }]}>
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item name="api_secret" label={t('form.apiSecret')}
          extra={data?.secret_configured ? t('form.secretKeep', { fingerprint: data.secret_fingerprint }) : t('form.secretUnset')}
          rules={[{ min: 16 }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
        {data?.secret_configured ? <Form.Item>
          <Switch checked={clearSecret} onChange={setClearSecret} aria-label={t('form.clearSecret')} /> {t('form.clearSecret')}
        </Form.Item> : null}
        <Form.Item name="source_domain" label={t('form.sourceDomain')} extra={t('form.sourceDomainExtra')}>
          <Input autoComplete="off" placeholder="control.example.com" />
        </Form.Item>
        <Form.Item name="origin_sources" label={t('form.originSources')} extra={t('form.sourcesExtra')}
          rules={[{ required: true, type: 'array', min: 1 }]}>
          <Select mode="multiple" options={sourceOptions(originSources)} aria-label={t('form.originSources')} />
        </Form.Item>
        <Form.Item name="edge_sources" label={t('form.edgeSources')} rules={[{ required: true, type: 'array', min: 1 }]}>
          <Select mode="multiple" options={sourceOptions(edgeSources)} aria-label={t('form.edgeSources')} />
        </Form.Item>
        </div>
        <Space wrap>
          <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('form.save')}</Button>
          <Button loading={test.isPending} disabled={!licensed} onClick={() => test.mutate()}>{t('form.test')}</Button>
        </Space>
      </Form>
    </Card>
    {data ? <Card title={t('state.title')}>
      <Descriptions column={2} size="small">
        <Descriptions.Item label={t('state.active')}>
          <Tag color={data.active ? 'green' : undefined}>{data.active ? t('state.activeYes') : t('state.activeNo')}</Tag>
        </Descriptions.Item>
        <Descriptions.Item label={t('state.accountChecked')}>{formatTime(data.account_checked_at)}</Descriptions.Item>
        <Descriptions.Item label={t('state.async')}>{data.account_checked_at ? (data.async_capable ? t('state.asyncYes') : t('state.asyncNo')) : '—'}</Descriptions.Item>
        <Descriptions.Item label={t('state.quota')}>{data.account_checked_at ? `${data.monthly_used} / ${data.monthly_limit}` : '—'}</Descriptions.Item>
        {data.account_error_code ? <Descriptions.Item label={t('state.accountError')} span={2}>
          <Typography.Text type="danger">{t(`errors.${data.account_error_code}`, { defaultValue: data.account_error_code })}</Typography.Text>
        </Descriptions.Item> : null}
      </Descriptions>
    </Card> : null}
    {data ? <NodeProbeCard token={token} /> : null}
  </Space>
}
