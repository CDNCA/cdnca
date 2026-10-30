import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Popconfirm, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { wafRuleSubscriptionsApi, type TenantWAFRuleSubscription } from '../../api/wafRuleSubscriptions'
import { localizedUnknownApiError } from '../../i18n/apiError'
import '../../i18n/rulePacks'

// WAFSubscriptionSection is the tenant's "WAF 规则库订阅" on the rule pack
// page (PA-25): subscribing gives the tenant a user layer rule pack
// (downloaded, not enabled); a subscription update adds a pack version and
// the published sites mounting an older one wait to be published again.
export default function WAFSubscriptionSection({ accessToken, canManage, onChanged, onOpenSite }: {
  accessToken: string
  canManage: boolean
  onChanged: () => void
  onOpenSite: (siteID: string) => void
}) {
  const { t } = useTranslation('rulePacks')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const query = useQuery({ queryKey: ['waf-rule-subscriptions', 'available'], retry: false,
    queryFn: () => wafRuleSubscriptionsApi.available(accessToken) })
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['waf-rule-subscriptions', 'available'] })
    onChanged()
  }
  const failure = (error: unknown) => void feedback.error(error instanceof ApiError && error.code === 'waf_subscription_not_ready'
    ? t('subscriptions.notReady') : localizedUnknownApiError(error, t('notices.failed')))
  const subscribe = useMutation({
    mutationFn: (id: string) => wafRuleSubscriptionsApi.subscribe(accessToken, id),
    onSuccess: () => { void messageApi.success(t('subscriptions.subscribed')); refresh() },
    onError: failure,
  })
  const unsubscribe = useMutation({
    mutationFn: (id: string) => wafRuleSubscriptionsApi.unsubscribe(accessToken, id),
    onSuccess: () => { void messageApi.success(t('subscriptions.unsubscribed')); refresh() },
    onError: failure,
  })
  if (query.isError) return null
  const items = query.data ?? []
  const columns: TableColumnsType<TenantWAFRuleSubscription> = [
    { title: t('subscriptions.name'), dataIndex: 'name', render: (_, item) => <span>
      <strong>{item.name}</strong>{item.deleted ? <> <Tag>{t('subscriptions.deleted')}</Tag></> : null}
      {item.description ? <><br /><small>{item.description}</small></> : null}
    </span> },
    { title: t('subscriptions.version'), key: 'version', render: (_, item) => t('subscriptions.feed', { feed: item.feed_version, rules: item.rule_count }) },
    { title: t('subscriptions.pack'), key: 'pack', render: (_, item) => {
      if (!item.pack) return <Typography.Text type="secondary">{t('subscriptions.notSubscribed')}</Typography.Text>
      const pack = item.pack
      return <Space direction="vertical" size={2}>
        <span><code>{pack.pack_id}</code><br /><small>{t('subscriptions.packVersion', { current: pack.current_version, latest: pack.latest_version })}</small></span>
        {pack.pending_sites.length > 0 ? <Alert type="warning" showIcon role="status"
          message={t('subscriptions.pending', { domains: pack.pending_sites.map((site) => site.domain).join('、') })}
          action={<Space direction="vertical" size={2}>{pack.pending_sites.map((site) => <Button key={site.site_id} size="small" type="primary"
            aria-label={`${t('subscriptions.publish')} ${site.domain}`} onClick={() => onOpenSite(site.site_id)}>{t('subscriptions.publish')}</Button>)}</Space>} /> : null}
      </Space>
    } },
    { title: t('subscriptions.actions'), key: 'actions', width: 110, render: (_, item) => !canManage ? null : item.subscribed
      ? <Popconfirm title={t('subscriptions.unsubscribeConfirm')} onConfirm={() => unsubscribe.mutate(item.id)}>
        <Button size="small" loading={unsubscribe.isPending && unsubscribe.variables === item.id}>{t('subscriptions.unsubscribe')}</Button>
      </Popconfirm>
      : <Button size="small" type="primary" disabled={item.deleted} loading={subscribe.isPending && subscribe.variables === item.id}
        onClick={() => subscribe.mutate(item.id)}>{t('subscriptions.subscribe')}</Button> },
  ]
  return <Card size="small" title={t('subscriptions.title')}>
    {messageContext}
    <Typography.Paragraph type="secondary" className="density-note">{t('subscriptions.intro')}</Typography.Paragraph>
    <Table rowKey="id" size="small" columns={columns} dataSource={items} loading={query.isPending} pagination={false}
      locale={{ emptyText: t('subscriptions.none') }} />
  </Card>
}
