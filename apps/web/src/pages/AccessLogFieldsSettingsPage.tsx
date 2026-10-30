import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Checkbox, InputNumber, Result, Space, Spin, Tag, Typography } from 'antd'
import { useFeedbackMessage, FeedbackWhen } from '@cdnca/ui'
import { CheckCircle, RefreshCw, Rocket, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
  accessLogFieldKeys,
  newSystemConfigurationIdempotencyKey,
  newSystemConfigurationRequestId,
  systemConfigurationApi,
  type AccessLogFieldKey,
  type SystemConfigurationDocument,
} from '../api/systemConfiguration'
import { systemCleanupSettingsApi, type PlatformSystemCleanupDocument } from '../api/systemCleanupSettings'
import { useSessionStore } from '../auth/session'
import { accessLogFieldsNamespace as namespace } from '../i18n/accessLogFieldsSettings'
import { PendingCategoriesNotice, usePendingActivationConfirm } from './system-settings/PendingCategories'

type Document = SystemConfigurationDocument<'access_log_fields'>

/**
 * The field catalog as the settings page groups it (libs/edgeconfig
 * AccessLogFieldCatalog): group, and the typical stored bytes of one value.
 */
const catalog: ReadonlyArray<{ key: AccessLogFieldKey; group: string; bytes: number }> = [
  { key: 'client_family', group: 'client', bytes: 2 },
  { key: 'client_geo', group: 'client', bytes: 8 },
  { key: 'referer', group: 'request_headers', bytes: 80 },
  { key: 'user_agent', group: 'request_headers', bytes: 120 },
  { key: 'accept_language', group: 'request_headers', bytes: 30 },
  { key: 'content_type', group: 'response_headers', bytes: 25 },
  { key: 'content_encoding', group: 'response_headers', bytes: 6 },
  { key: 'origin_timing', group: 'origin', bytes: 12 },
  { key: 'upstream_addr', group: 'origin', bytes: 20 },
  { key: 'cache_control', group: 'cache', bytes: 25 },
  { key: 'x_forwarded_for', group: 'security', bytes: 30 },
  { key: 'x_real_ip', group: 'security', bytes: 16 },
  { key: 'block_page', group: 'security', bytes: 1 },
  { key: 'ja4', group: 'tls_fingerprint', bytes: 36 },
]
const groups = ['client', 'request_headers', 'response_headers', 'origin', 'cache', 'security', 'tls_fingerprint'] as const
/** edgeconfig.DefaultAccessLogFields. */
export const defaultAccessLogFields: AccessLogFieldKey[] = ['client_family', 'client_geo', 'referer', 'user_agent', 'content_type', 'origin_timing', 'block_page', 'ja4']
/** Average stored bytes of the basic fields. */
const basicBytes = 220

function hasPermission(principal: Principal, permission: string): boolean {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

function canonical(fields: readonly AccessLogFieldKey[]): AccessLogFieldKey[] {
  return accessLogFieldKeys.filter((key) => fields.includes(key))
}

function sameFields(left: readonly AccessLogFieldKey[], right: readonly AccessLogFieldKey[]) {
  return canonical(left).join(',') === canonical(right).join(',')
}

/** Estimated uncompressed size of 10^8 entries with fields selected. */
export function estimatedSize(fields: readonly AccessLogFieldKey[]): string {
  const bytes = (basicBytes + catalog.filter((item) => fields.includes(item.key)).reduce((sum, item) => sum + item.bytes, 0)) * 1e8
  return bytes >= 1e12 ? `${(bytes / 1e12).toFixed(1)} TB` : `${Math.round(bytes / 1e9)} GB`
}

export default function AccessLogFieldsSettingsPage() {
  const { t } = useTranslation(namespace)
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal) return null
  if (principal.scope_kind !== 'platform' || !hasPermission(principal, 'system_configuration.read')) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  return <AccessLogFieldsContent canManage={hasPermission(principal, 'system_configuration.manage')} />
}

function AccessLogFieldsContent({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation(namespace)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [failure, setFailure] = useState<string | null>(null)
  const [selected, setSelected] = useState<AccessLogFieldKey[]>([])
  const queryKey = ['system-configuration', 'access_log_fields'] as const
  const token = () => useSessionStore.getState().accessToken ?? ''
  const confirmPending = usePendingActivationConfirm('access_log_fields')

  const query = useQuery({ queryKey, queryFn: () => systemConfigurationApi.get(token(), 'access_log_fields') })
  const document = query.data
  useEffect(() => {
    if (document) setSelected(canonical(document.value.fields))
  }, [document])

  const save = useMutation({
    mutationFn: async () => {
      if (!document) throw new Error('not loaded')
      return systemConfigurationApi.put(token(), 'access_log_fields', { fields: canonical(selected) }, document.head_revision,
        newSystemConfigurationIdempotencyKey('access_log_fields'), newSystemConfigurationRequestId('access_log_fields'))
    },
    onSuccess: (next) => {
      setFailure(null)
      queryClient.setQueryData<Document>(queryKey, next)
      messageApi.success(t('notices.saved'))
    },
    onError: (error) => setFailure(errorText(t, error, 'errors.write')),
  })

  const lifecycle = useMutation({
    mutationFn: async (kind: 'preflight' | 'activate') => {
      if (!document) throw new Error('not loaded')
      if (kind === 'preflight') {
        return systemConfigurationApi.preflight(token(), document.revision, document.snapshot_sha256,
          newSystemConfigurationIdempotencyKey('access_log_fields'), newSystemConfigurationRequestId('access_log_fields'),
          document.pending_categories)
      }
      return systemConfigurationApi.activate(token(), document.revision, document.active_revision,
        newSystemConfigurationIdempotencyKey('access_log_fields'), newSystemConfigurationRequestId('access_log_fields'),
        document.pending_categories)
    },
    onSuccess: (result) => {
      setFailure(null)
      queryClient.setQueryData<Document>(queryKey, (current) => current && current.revision === result.revision ? {
        ...current, status: result.status,
        active_revision: result.status === 'active' ? result.revision : current.active_revision,
      } : current)
      messageApi.success(t(result.status === 'active' ? 'notices.activated' : 'notices.validated'))
    },
    onError: (error) => setFailure(errorText(t, error, 'errors.lifecycle')),
  })

  if (query.isPending) return <Spin aria-label={t('loading')} />
  if (query.isError || !document) {
    return <Result status="warning" title={t('errors.load')} extra={<Button onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>} />
  }

  const statusText = document.head_revision === 0
    ? t('status.none')
    : t(`status.${document.status === 'active' ? 'active' : document.status === 'validated' ? 'validated' : 'draft'}`, { revision: document.revision })
  const busy = save.isPending || lifecycle.isPending
  const dirty = !sameFields(selected, document.value.fields)
  const toggle = (key: AccessLogFieldKey, on: boolean) =>
    setSelected((current) => canonical(on ? [...current, key] : current.filter((item) => item !== key)))

  return (
    <div className="access-log-fields-settings">
      {messageContext}
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <div>
          <Typography.Title level={4}>{t('title')}</Typography.Title>
          <Typography.Text type="secondary">{t('description')}</Typography.Text>
        </div>
        <Space>
          <span>{t('status.label')}</span>
          <Tag color={document.status === 'active' ? 'green' : 'orange'}>{statusText}</Tag>
          <Button icon={<RefreshCw size={14} />} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
        </Space>
        <PendingCategoriesNotice current="access_log_fields" pending={document.pending_categories} />
        {failure && <FeedbackWhen title={failure} />}
        <Alert type="info" showIcon message={t('basic.title')} description={t('basic.description')} />
        {groups.map((group) => (
          <Card key={group} size="small" title={t(`groups.${group}`)} data-testid={`access-log-group-${group}`}>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              {catalog.filter((item) => item.group === group).map((item) => (
                <div key={item.key}>
                  <Checkbox checked={selected.includes(item.key)} disabled={!canManage || busy}
                    onChange={(event) => toggle(item.key, event.target.checked)} data-testid={`access-log-field-${item.key}`}>
                    <Typography.Text strong>{t(`fields.${item.key}.label`)}</Typography.Text>
                    {' '}<Typography.Text type="secondary">{t('cost', { bytes: item.bytes })}</Typography.Text>
                  </Checkbox>
                  <div style={{ paddingInlineStart: 24 }}>
                    <Typography.Text type="secondary">{t(`fields.${item.key}.usage`)}</Typography.Text>
                  </div>
                </div>
              ))}
            </Space>
          </Card>
        ))}
        <Typography.Text data-testid="access-log-estimate">
          {t('selectedCount', { count: selected.length })} · {t('costBasic', { size: estimatedSize(selected) })}
        </Typography.Text>
        {canManage && (
          <Space wrap>
            <Button disabled={busy || sameFields(selected, defaultAccessLogFields)} onClick={() => setSelected(defaultAccessLogFields)}>
              {t('resetDefault')}
            </Button>
            <Button type="primary" icon={<Save size={14} />} loading={save.isPending} disabled={busy || !dirty}
              onClick={() => save.mutate()}>{t('actions.save')}</Button>
            <Button icon={<CheckCircle size={14} />} disabled={document.status !== 'draft' || busy || dirty}
              onClick={() => lifecycle.mutate('preflight')}>{t('actions.preflight')}</Button>
            <Button icon={<Rocket size={14} />} disabled={document.status !== 'validated' || busy || dirty}
              onClick={() => confirmPending(document.pending_categories, () => lifecycle.mutate('activate'))}>{t('actions.activate')}</Button>
          </Space>
        )}
        <RetentionCard canManage={canManage} />
      </Space>
    </div>
  )
}

/** The access log retention: systemcleanup access_logs_days (the same setting the cleanup page edits). */
function RetentionCard({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation(namespace)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [days, setDays] = useState<number | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const queryKey = ['system-cleanup-settings'] as const
  const token = () => useSessionStore.getState().accessToken ?? ''
  const query = useQuery({ queryKey, queryFn: () => systemCleanupSettingsApi.get(token()) })
  const document = query.data
  useEffect(() => {
    if (document) setDays(document.value.access_logs_days)
  }, [document])
  const save = useMutation({
    mutationFn: async (value: number) => {
      if (!document) throw new Error('not loaded')
      return systemCleanupSettingsApi.put(token(), document.revision, { ...document.value, access_logs_days: value })
    },
    onSuccess: (next) => {
      setFailure(null)
      queryClient.setQueryData<PlatformSystemCleanupDocument>(queryKey, next)
      messageApi.success(t('retention.saved'))
    },
    onError: (error) => setFailure(errorText(t, error, 'errors.write')),
  })
  return (
    <Card size="small" title={t('retention.title')} data-testid="access-log-retention">
      {messageContext}
      {query.isPending ? <Spin /> : query.isError || !document ? (
        <Alert type="warning" showIcon message={t('retention.loadError')} />
      ) : (
        <Space direction="vertical" size={8}>
          {failure && <FeedbackWhen title={failure} />}
          <Space wrap>
            <label htmlFor="access-log-retention-days">{t('retention.label')}</label>
            <InputNumber id="access-log-retention-days" min={0} max={3650} precision={0} value={days}
              disabled={!canManage || save.isPending} onChange={(value) => setDays(value)} />
            {canManage && (
              <Button loading={save.isPending} disabled={days === null || days === document.value.access_logs_days}
                onClick={() => days !== null && save.mutate(days)}>{t('retention.save')}</Button>
            )}
          </Space>
          <Typography.Text type="secondary">{t('retention.help')}</Typography.Text>
        </Space>
      )}
    </Card>
  )
}

function errorText(t: (key: string) => string, error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return t('errors.permissionDenied')
    if (error.code === 'system_configuration_pending_categories_changed') return t('errors.pendingChanged')
    if (error.status === 409 || error.code === 'system_configuration_revision_conflict') return t('errors.conflict')
    if (error.status === 400 || error.code === 'system_configuration_validation_error') return t('errors.invalid')
  }
  return t(fallback)
}
