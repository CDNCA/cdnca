import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Space, Table, Typography } from 'antd'
import { CheckCircle2, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { domainOwnershipApi, newDomainTrustKey, type DomainConflict, type DomainOwnership, type OwnershipMethod } from '../../api/domainTrust'
import { useSessionStore } from '../../auth/session'
import '../../i18n/domainTrust'
import { FeedbackWhen } from '@cdnca/ui'

function codeOf(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

/**
 * The verification step for one domain: start a challenge, show the TXT
 * record (or HTTP file), check it, and once verified list and claim other
 * accounts' conflicting sites. Used on the verified domains page and inside
 * the site create form when a write is refused with domain_ownership_required.
 */
export function DomainOwnershipPanel({ domain, initial, onVerified }: {
  domain: string
  /** A known ownership record (e.g. a listed row) to show instead of starting over. */
  initial?: DomainOwnership
  onVerified?: (item: DomainOwnership) => void
}) {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [item, setItem] = useState<DomainOwnership | null>(initial ?? null)
  const [selected, setSelected] = useState<string[]>([])
  const errorText = (error: unknown) => t(`errors.${codeOf(error)}`, { defaultValue: t('errors.failed', { code: codeOf(error) }) })
  const start = useMutation({
    mutationFn: (method: OwnershipMethod) => domainOwnershipApi.start(token, domain, method),
    onSuccess: (value) => {
      setItem(value)
      if (value.status === 'verified') onVerified?.(value)
      void client.invalidateQueries({ queryKey: ['domainOwnerships'] })
    },
  })
  const check = useMutation({
    mutationFn: () => domainOwnershipApi.check(token, domain),
    onSuccess: (value) => {
      setItem(value)
      if (value.status === 'verified') {
        void message.success(t('user.verified'))
        onVerified?.(value)
      }
      void client.invalidateQueries({ queryKey: ['domainOwnerships'] })
    },
  })
  const verified = item?.status === 'verified'
  const conflicts = useQuery({
    queryKey: ['domainConflicts', item?.apex],
    queryFn: () => domainOwnershipApi.conflicts(token, item?.apex ?? domain),
    enabled: verified && !!token,
  })
  const claim = useMutation({
    mutationFn: () => domainOwnershipApi.claim(token, item?.apex ?? domain, selected, newDomainTrustKey('domain-claim')),
    onSuccess: (result) => {
      void message.success(t('user.claimed', { count: result.suspended_sites }))
      setSelected([])
      void client.invalidateQueries({ queryKey: ['domainConflicts'] })
    },
  })
  const failure = item?.last_failure_code && !verified
    ? t(`user.failures.${item.last_failure_code}`, { defaultValue: item.last_failure_code }) : ''
  const error = start.error ?? check.error ?? claim.error
  return (
    <div className="domain-ownership-panel" data-testid="domain-ownership-panel">
      {error ? <FeedbackWhen title={errorText(error)} /> : null}
      {!item ? (
        <Button type="primary" loading={start.isPending} onClick={() => start.mutate('dns_txt')}>{t('user.start')}</Button>
      ) : verified ? (
        <Alert type="success" showIcon icon={<CheckCircle2 size={16} />} message={`${item.apex} · ${t('user.verified')}`} />
      ) : (
        <>
          <Typography.Paragraph>{item.method === 'dns_txt' ? t('user.txtStep') : t('user.httpStep')}</Typography.Paragraph>
          <Descriptions size="small" column={1} bordered>
            {item.method === 'dns_txt' ? <>
              <Descriptions.Item label={t('user.recordName')}><Typography.Text code copyable>{item.txt_name}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label={t('user.recordValue')}><Typography.Text code copyable>{item.token}</Typography.Text></Descriptions.Item>
            </> : <>
              <Descriptions.Item label={t('user.fileURL')}><Typography.Text code copyable>{item.http_url}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label={t('user.fileContent')}><Typography.Text code copyable>{item.token}</Typography.Text></Descriptions.Item>
            </>}
          </Descriptions>
          {failure ? <FeedbackWhen type="warning" title={t('user.notYet', { reason: failure })} /> : null}
          <Space wrap style={{ marginTop: 12 }}>
            <Button type="primary" icon={<RefreshCw size={14} />} loading={check.isPending} onClick={() => check.mutate()}>{t('user.check')}</Button>
            <Button loading={start.isPending} onClick={() => start.mutate(item.method === 'dns_txt' ? 'http_file' : 'dns_txt')}>
              {item.method === 'dns_txt' ? t('user.switchHTTP') : t('user.switchTXT')}
            </Button>
          </Space>
        </>
      )}
      {verified && (conflicts.data?.length ?? 0) > 0 ? (
        <div style={{ marginTop: 16 }}>
          <Typography.Title level={5}>{t('user.conflicts')}</Typography.Title>
          <Typography.Paragraph type="secondary">{item?.method === 'dns_txt' ? t('user.conflictsHint') : t('user.claimNeedsTXT')}</Typography.Paragraph>
          <Table<DomainConflict> rowKey="domain" size="small" pagination={false} dataSource={conflicts.data ?? []}
            rowSelection={{ selectedRowKeys: selected, onChange: (keys) => setSelected(keys as string[]),
              getCheckboxProps: (row) => ({ disabled: !row.claimable || item?.method !== 'dns_txt' }) }}
            columns={[{ title: t('user.domain'), dataIndex: 'domain' }, { title: t('hits.site'), dataIndex: 'site_count' }]} />
          <Button danger style={{ marginTop: 12 }} disabled={selected.length === 0} loading={claim.isPending} onClick={() => claim.mutate()}>{t('user.claim')}</Button>
        </div>
      ) : null}
    </div>
  )
}
