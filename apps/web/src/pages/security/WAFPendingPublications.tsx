import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Table, Tag, type TableColumnsType } from 'antd'
import { FeedbackWhen } from '@cdnca/ui'
import { Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'

import type { SecurityPolicy } from '../../api/securityPolicies'
import { wafRuleSubscriptionsApi, type WAFPendingPublication } from '../../api/wafRuleSubscriptions'
import { ApiError } from '../../api/auth'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/wafRuleSubscriptions'

// "订阅已更新、待发布": sites whose subscribed WAF library has a newer version
// than the published one. "去发布" only opens the security activation panel
// with the site, library and last target nodes filled in; the operator
// still confirms the release (no automatic publication).
export default function WAFPendingPublications({ accessToken, policies, canManage }: {
  accessToken: string
  policies: SecurityPolicy[]
  canManage: boolean
}) {
  const { t } = useTranslation('securityPolicies')
  const [searchParams, setSearchParams] = useSearchParams()
  const query = useQuery({
    queryKey: ['waf-pending-publications'],
    retry: false,
    queryFn: () => wafRuleSubscriptionsApi.pendingPublications(accessToken),
  })
  // SEC-ACCOUNT-03: a failed read is "unknown", never "nothing waiting to publish".
  if (query.isError) {
    const denied = query.error instanceof ApiError && query.error.status === 403
    return <FeedbackWhen title={t(denied ? 'wafPending.forbidden' : 'wafPending.loadFailed')}
      detail={denied ? undefined : localizedUnknownApiError(query.error, t('errors.request_failed'))}
      action={denied ? undefined : <Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
  }
  const items = query.data ?? []
  if (items.length === 0) return null
  const libraryName = (id: string) => policies.find((policy) => policy.id === id)?.name ?? t('wafPending.unknownLibrary')
  const open = (item: WAFPendingPublication) => {
    const next = new URLSearchParams(searchParams)
    next.set('site_id', item.site_id)
    next.set('policy_id', item.policy_id)
    // The control plane targets the site's package line groups (10-22 自动下发).
    next.delete('target_node_ids')
    setSearchParams(next)
  }
  const columns: TableColumnsType<WAFPendingPublication> = [
    { title: t('wafPending.columns.site'), dataIndex: 'domain' },
    { title: t('wafPending.columns.library'), dataIndex: 'policy_id', render: (id: string) => libraryName(id) },
    { title: t('wafPending.columns.version'), key: 'version',
      render: (_, item) => t('wafPending.version', { active: item.active_version, latest: item.latest_version }) },
    { title: t('wafPending.columns.actions'), key: 'actions', render: (_, item) => item.publishing
      ? <Tag color="processing">{t('wafPending.publishing')}</Tag>
      : <Button size="small" type="primary" icon={<Upload size={13} />} disabled={!canManage} onClick={() => open(item)}>{t('wafPending.publish')}</Button> },
  ]
  return <Alert className="identity-alert waf-pending-publications" type="warning" showIcon role="status"
    message={t('wafPending.title', { count: items.length })}
    description={<>
      <p>{t('wafPending.description')}</p>
      <Table rowKey="site_id" size="small" columns={columns} dataSource={items} pagination={false} />
    </>} />
}
