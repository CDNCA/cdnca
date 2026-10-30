import { Alert, Button, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import type { MarketListingBatchItem } from '../../api/market'
import { FeedbackWhen } from '@cdnca/ui'
import { retryNodes, unpublished } from './listingModel'

const color: Record<MarketListingBatchItem['status'], string> = { created: 'success', existing: 'default', failed: 'error', in_progress: 'processing' }

// Result page of a batch: one row per item, failed ones can be fixed in the
// form above and resubmitted (the others come back as "existing"). Offers
// made but not published are not a success: they are retried too (B19).
export function ListingBatchResults({ items, names, onRetry, retrying }: {
  items: MarketListingBatchItem[]
  names: Record<string, string>
  onRetry: () => void
  retrying: boolean
}) {
  const { t, i18n } = useTranslation('nodeMarket')
  const failed = items.filter((i) => i.status === 'failed' || i.status === 'in_progress').length
  const drafts = unpublished(items).length
  const retry = items.filter((i) => retryNodes([i]).length > 0).length
  const reason = (i: MarketListingBatchItem) => {
    if (!i.error) return null
    const code = i.error.replace(/^publish_/, '')
    const text = i18n.exists(`nodeMarket:listing.refused.${code}`) ? t(`listing.refused.${code}`)
      : i18n.exists(`nodeMarket:bulk.errors.${code}`) ? t(`bulk.errors.${code}`) : t('batch.errorCode', { code })
    const floor = i.detail?.floor !== undefined && i.detail.metric ? t('batch.floorDetail', { metric: t(`limitMetrics.${i.detail.metric}`), floor: i.detail.floor }) : ''
    return <Typography.Text type="danger">{i.error.startsWith('publish_') ? t('batch.publishFailed', { reason: text }) : text}{floor ? ` ${floor}` : ''}</Typography.Text>
  }
  const summary = t('batch.summary', {
    total: items.length, created: items.filter((i) => i.status === 'created').length,
    existing: items.filter((i) => i.status === 'existing').length, failed }) + (drafts ? t('batch.summaryUnpublished', { count: drafts }) : '')
  return (
    <Space direction="vertical" style={{ width: '100%', marginTop: 16 }} aria-label={t('batch.results')}>
      <Typography.Title level={5}>{t('batch.results')}</Typography.Title>
      {retry ? <FeedbackWhen type="warning" title={summary} /> : <Alert type="success" showIcon message={summary} />}
      <Table<MarketListingBatchItem> rowKey={(i) => i.node_ids.join(',')} size="small" dataSource={items} pagination={{ pageSize: 20, hideOnSinglePage: true }}
        columns={[
          { title: t('batch.nodes'), key: 'nodes', render: (_: unknown, i) => i.node_ids.map((id) => names[id] ?? id.slice(0, 8)).join('、') },
          { title: t('batch.status'), key: 'status', render: (_: unknown, i) => <Tag color={color[i.status]}>{t(`batch.statuses.${i.status}`)}</Tag> },
          { title: t('batch.published'), key: 'published', render: (_: unknown, i) => i.published ? t(`states.${i.published}`, { defaultValue: i.published }) : '—' },
          { title: t('batch.removedPlugins'), key: 'removed', render: (_: unknown, i) => i.removed_plugins.length
            ? <Typography.Text type="warning">{t('batch.removed', { plugins: i.removed_plugins.join('、') })}</Typography.Text> : '—' },
          { title: t('batch.reason'), key: 'reason', render: (_: unknown, i) => reason(i) ?? '—' },
        ]} />
      {retry ? <Button onClick={onRetry} loading={retrying}>{t('batch.retry', { count: retry })}</Button> : null}
    </Space>
  )
}
