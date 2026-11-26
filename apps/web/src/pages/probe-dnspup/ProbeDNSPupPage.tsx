import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Descriptions, Form, Input, Result, Select, Skeleton, Space, Switch, Tag, Typography } from 'antd'
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
import { useProbeReason } from './probeErrors'
import { MatrixCard, OverridesCard, PurposesCard } from './UnifiedCards'
import { useFeedback, FeedbackWhen, PageHeader, PageSection, useFormSubmitError } from '@cdnca/ui'
import './ProbeDNSPupPage.css'

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

// api_secret omitted keeps the stored secret, "" clears it; clearing the key clears the stored secret with it (a
// secret is only ever sent with the key it was entered for).
function toInput(values: FormValues, clearSecret: boolean, secretConfigured: boolean): ProbeDNSPupInput {
  const input: ProbeDNSPupInput = {
    enabled: values.enabled, base_url: values.base_url.trim(), api_key: values.api_key?.trim() ?? '',
    source_domain: values.source_domain?.trim() ?? '', origin_sources: values.origin_sources, edge_sources: values.edge_sources,
  }
  const secret = values.api_secret?.trim()
  if (secret) input.api_secret = secret
  else if (clearSecret || (secretConfigured && !input.api_key)) input.api_secret = ''
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
  // Which button validates: saving needs the key pair only while enabled; the connection test always needs the key.
  const validating = useRef<'save' | 'test'>('save')
  const status = useQuery({ queryKey: ['probe-dnspup'], queryFn: () => probeDNSPupApi.status(token), enabled: Boolean(token) })
  const reason = useProbeReason(true)
  const secretConfigured = Boolean(status.data?.secret_configured)
  const validate = async (mode: 'save' | 'test') => {
    validating.current = mode
    try {
      return await form.validateFields()
    } finally {
      validating.current = 'save'
    }
  }

  useEffect(() => {
    const data = status.data
    if (!data) return
    form.setFieldsValue({ enabled: data.enabled, base_url: data.base_url, api_key: data.api_key, api_secret: undefined,
      source_domain: data.source_domain, origin_sources: data.origin_sources, edge_sources: data.edge_sources })
    setClearSecret(false)
  }, [status.data, form])

  const save = useMutation({
    mutationFn: async () => probeDNSPupApi.save(token, toInput(await validate('save'), clearSecret, secretConfigured),
      newIdempotencyKey('probe-dnspup-save')),
    onSuccess: (data: ProbeDNSPupStatus) => { client.setQueryData(['probe-dnspup'], data); void message.success(t('form.saved')) },
    onError: (error) => { markSubmitError(error, () => void feedback.error(reason(error))) },
  })
  const test = useMutation({
    mutationFn: async () => probeDNSPupApi.test(token, toInput(await validate('test'), false, false), newIdempotencyKey('probe-dnspup-test')),
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

  // one page card; every block below is a titled section of it (thin border, no nested cards).
  // The connection section opens with the account state as a one-row strip, then the fields on the density grid.
  return <PageSection className="probe-dnspup-page">
    <PageHeader title={t('title')} description={t('intro')} />
    <div className="probe-dnspup-sections">
      {data && !licensed ? <Alert type="warning" showIcon message={t('notLicensed')} action={<PurchaseModuleLink size="small" featureCode={probeDNSPupModule} />} /> : null}
      {data?.paused_until ? <Alert type="error" showIcon message={`${t('state.pausedUntil')} ${formatTime(data.paused_until)}`}
        description={`${t(`state.reasons.${data.pause_reason}`, { defaultValue: data.pause_reason })} (${data.pause_code})`} /> : null}
      <PageSection title={t('form.title')}>
        {status.isLoading ? <Skeleton active /> : <>
          {data ? <Descriptions className="probe-dnspup-strip" title={t('state.title')} bordered size="small" column={{ xs: 1, sm: 2, xl: 4 }}>
            <Descriptions.Item label={t('state.active')}>
              <Tag color={data.active ? 'green' : undefined}>{data.active ? t('state.activeYes') : t('state.activeNo')}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t('state.accountChecked')}>{formatTime(data.account_checked_at)}</Descriptions.Item>
            <Descriptions.Item label={t('state.async')}>{data.account_checked_at ? (data.async_capable ? t('state.asyncYes') : t('state.asyncNo')) : '—'}</Descriptions.Item>
            <Descriptions.Item label={t('state.quota')}>{data.account_checked_at ? `${data.monthly_used} / ${data.monthly_limit}` : '—'}</Descriptions.Item>
            {data.account_error_code ? <Descriptions.Item label={t('state.accountError')} span="filled">
              <Typography.Text type="danger">{t(`errors.${data.account_error_code}`, { defaultValue: data.account_error_code })}</Typography.Text>
            </Descriptions.Item> : null}
          </Descriptions> : null}
          <Form form={form} layout="vertical" disabled={!data} requiredMark={false}>
            <div className="density-form-grid probe-dnspup-form-grid">
              <Form.Item name="base_url" label={t('form.baseURL')} rules={[{ required: true, type: 'url' }]}>
                <Input placeholder="https://api.dnspup.com" autoComplete="off" />
              </Form.Item>
              <Form.Item name="api_key" label={t('form.apiKey')} dependencies={['enabled']}
                rules={[({ getFieldValue }) => ({ required: validating.current === 'test' || Boolean(getFieldValue('enabled')) }), { min: 8 }]}>
                <Input autoComplete="off" />
              </Form.Item>
              <Form.Item name="api_secret" label={t('form.apiSecret')} dependencies={['enabled']}
                rules={[({ getFieldValue }) => ({ required: validating.current === 'save' && Boolean(getFieldValue('enabled')) &&
                  (!secretConfigured || clearSecret) }), { min: 16 }]}
                extra={data?.secret_configured ? <Space size={[12, 0]} wrap>
                  <span>{t('form.secretKeep', { fingerprint: data.secret_fingerprint })}</span>
                  <Checkbox checked={clearSecret} onChange={(event) => setClearSecret(event.target.checked)}>{t('form.clearSecret')}</Checkbox>
                </Space> : t('form.secretUnset')}>
                <Input.Password autoComplete="new-password" />
              </Form.Item>
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
            <div className="probe-dnspup-actions">
              <span className="probe-dnspup-enabled">
                <Form.Item name="enabled" valuePropName="checked" noStyle><Switch id="probe-dnspup-enabled" disabled={!licensed} /></Form.Item>
                <label htmlFor="probe-dnspup-enabled">{t('form.enabled')}</label>
              </span>
              <Space wrap>
                <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>{t('form.save')}</Button>
                <Button loading={test.isPending} disabled={!licensed} onClick={() => test.mutate()}>{t('form.test')}</Button>
              </Space>
            </div>
          </Form>
        </>}
      </PageSection>
      {data ? <PurposesCard token={token} connection={data} /> : null}
      {data ? <NodeProbeCard token={token} connection={data} /> : null}
      {data ? <OverridesCard token={token} /> : null}
      {data ? <MatrixCard token={token} initialNode={new URLSearchParams(window.location.search).get('node') ?? undefined} /> : null}
    </div>
  </PageSection>
}
