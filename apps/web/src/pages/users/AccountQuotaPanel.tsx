import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Alert, Button, Form, InputNumber, Table, Tag } from 'antd'
import { useFeedbackMessage } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { cacheOperationsApi, type CacheAccountLimits, type CacheDailyQuota } from '../../api/cacheOperations'
import { formatDateTime, formatNumber } from '../../i18n/formatters'
import '../../i18n/cacheOperations'
import './ResellerPanel.css'
import './AccountQuotaPanel.css'

type QuotaKey = 'url_purge' | 'directory_purge' | 'prewarm'
type LimitField = keyof CacheAccountLimits

const quotas: { key: QuotaKey; field: LimitField; label: string; maximum: number }[] = [
  { key: 'url_purge', field: 'url_purge_limit', label: 'baseline.modes.url', maximum: 10_000_000 },
  { key: 'directory_purge', field: 'directory_purge_limit', label: 'baseline.modes.directory', maximum: 1_000_000 },
  { key: 'prewarm', field: 'prewarm_limit', label: 'baseline.modes.prewarm', maximum: 10_000_000 },
]

function errorText(error: unknown, t: (key: string) => string): string {
  if (error instanceof ApiError && error.code === 'revision_conflict') return t('accountQuota.stale')
  if (error instanceof ApiError && error.code === 'permission_denied') return t('accountQuota.noPermission')
  const known = new Set(['authentication_required', 'invalid_request', 'not_found', 'request_cancelled', 'service_unavailable', 'network_error', 'invalid_response'])
  return error instanceof ApiError && known.has(error.code) ? t(`errors.${error.code}`) : t('errors.request_failed')
}

/**
 * 用户编辑「刷新预热额度」页签（fix-cachequota）：该账号今日三项已用/上限，「刷新」读最新，
 * 可单独设置三项上限（留空 = 跟随系统设置默认值）。与代理商页签一样独立保存，不随用户资料的「确定」提交。
 */
export default function AccountQuotaPanel({ scopeID, accessToken, canManage }: {
  scopeID: string
  accessToken: () => string | null
  /** identity.users.manage 或 platform.admin：能保存单独设置。 */
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('cacheOperations')
  const [messageApi, messageContext] = useFeedbackMessage()
  const [form] = Form.useForm<CacheAccountLimits>()
  const [error, setError] = useState<unknown>(null)
  const query = useQuery({
    queryKey: ['cache-account-quota', scopeID],
    queryFn: () => {
      const token = accessToken()
      if (!token) throw new ApiError('session changed', 401, 'authentication_required')
      return cacheOperationsApi.dailyUsage(token, { kind: 'admin', scopeId: scopeID })
    },
    retry: false,
    refetchOnWindowFocus: false,
  })
  const usage = query.data
  useEffect(() => {
    if (!usage) return
    form.setFieldsValue({
      url_purge_limit: usage.url_purge.override,
      directory_purge_limit: usage.directory_purge.override,
      prewarm_limit: usage.prewarm.override,
    })
  }, [form, usage])
  const mutation = useMutation({
    mutationFn: ({ revision, limits }: { revision: number; limits: CacheAccountLimits }) => {
      const token = accessToken()
      if (!token) throw new ApiError('session changed', 401, 'authentication_required')
      return cacheOperationsApi.setAccountLimits(token, scopeID, revision, limits)
    },
    onSuccess: () => {
      setError(null)
      messageApi.success(t('accountQuota.saved'))
      void query.refetch()
    },
    onError: (failure) => {
      setError(failure)
      if (failure instanceof ApiError && failure.code === 'revision_conflict') void query.refetch()
    },
  })

  if (query.isError && !usage) {
    return (
      <div className="user-form-tab-panel reseller-panel">
        <Alert type="error" showIcon message={t('accountQuota.loadFailed')} description={errorText(query.error, t)}
          action={<Button size="small" onClick={() => void query.refetch()}>{t('accountQuota.retry')}</Button>} />
      </div>
    )
  }
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const busy = query.isFetching || mutation.isPending
  const rows = usage ? quotas.map((item) => ({ ...item, quota: usage[item.key] as CacheDailyQuota })) : []
  const save = () => {
    if (!usage) return
    void form.validateFields().then((values) => {
      const normalize = (value: number | null | undefined) => (typeof value === 'number' ? value : null)
      mutation.mutate({
        revision: usage.revision,
        limits: {
          url_purge_limit: normalize(values.url_purge_limit),
          directory_purge_limit: normalize(values.directory_purge_limit),
          prewarm_limit: normalize(values.prewarm_limit),
        },
      })
    }, () => undefined)
  }

  return (
    <div className="user-form-tab-panel reseller-panel" data-testid="account-quota-panel">
      {messageContext}
      <p className="reseller-panel-help">{t('accountQuota.help')}</p>
      {error ? <Alert className="identity-alert" type={error instanceof ApiError && error.code === 'revision_conflict' ? 'warning' : 'error'}
        showIcon message={errorText(error, t)} onClose={() => setError(null)} closable /> : null}

      <div className="user-form-section-title"><span>{t('accountQuota.todayTitle')}</span></div>
      <Table<(typeof rows)[number]>
        size="small"
        rowKey="key"
        pagination={false}
        loading={query.isPending}
        dataSource={rows}
        scroll={{ x: 'max-content' }}
        columns={[
          { title: t('accountQuota.columns.quota'), key: 'quota', render: (_, row) => t(row.label) },
          { title: t('accountQuota.columns.used'), key: 'used', align: 'right', render: (_, row) => formatNumber(row.quota.used, locale) },
          { title: t('accountQuota.columns.limit'), key: 'limit', align: 'right', render: (_, row) => formatNumber(row.quota.limit, locale) },
          { title: t('accountQuota.columns.remaining'), key: 'remaining', align: 'right', render: (_, row) => formatNumber(row.quota.remaining, locale) },
          {
            title: t('accountQuota.columns.source'), key: 'source',
            render: (_, row) => row.quota.override === null
              ? <Tag>{t('accountQuota.sourceDefault')}</Tag>
              : <Tag color="blue">{t('accountQuota.sourceOverride')}</Tag>,
          },
        ]}
      />
      <div className="account-quota-toolbar">
        <span className="reseller-panel-muted">
          {usage ? t('accountQuota.resetsAt', { time: formatDateTime(usage.resets_at, locale) }) : null}
        </span>
        <Button size="small" loading={query.isFetching && !query.isPending} onClick={() => void query.refetch()}>
          {t('accountQuota.refresh')}
        </Button>
      </div>

      <div className="user-form-section-title"><span>{t('accountQuota.limitsTitle')}</span></div>
      <Form form={form} component="div" layout="horizontal" labelCol={{ flex: '110px' }} wrapperCol={{ flex: 'auto' }}
        disabled={busy || !usage || !canManage} requiredMark={false}>
        {quotas.map((item) => {
          const defaultLimit = usage?.[item.key].default_limit ?? 0
          return (
            <Form.Item key={item.field} name={item.field} label={t(item.label)}
              extra={t('accountQuota.followDefault', { count: formatNumber(defaultLimit, locale) })}>
              <InputNumber min={0} max={item.maximum} precision={0} aria-label={t(item.label)}
                placeholder={t('accountQuota.defaultPlaceholder', { count: formatNumber(defaultLimit, locale) })}
                addonAfter={t('accountQuota.perDay')} />
            </Form.Item>
          )
        })}
        <Form.Item label=" " colon={false} extra={canManage ? undefined : t('accountQuota.noPermission')}>
          <Button type="primary" loading={mutation.isPending} disabled={busy || !usage || !canManage} onClick={save}>
            {t('accountQuota.save')}
          </Button>
        </Form.Item>
      </Form>
    </div>
  )
}

