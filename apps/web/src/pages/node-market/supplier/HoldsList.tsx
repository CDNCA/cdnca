import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketSupplierApi, type HoldRow } from '../../../api/marketSupplier'
import { LoadFailure, Short } from './shared'
import { useErrorText, useTime, useToken } from './hooks'

// ADR 0012 §15 / U1: the paused/stopped slots, as a supplier (holds on what I
// sold) or as a subscriber (holds on what I bought). Same market query.
export function HoldsList({ role }: { role: 'seller' | 'buyer' }) {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const [cursors, setCursors] = useState<string[]>([])
  const cursor = cursors.at(-1)
  const query = useQuery({
    queryKey: ['nodeMarket', 'holds', role, cursor], enabled: !!token, retry: false,
    queryFn: () => (role === 'seller' ? marketSupplierApi.sellerHolds(token, cursor) : marketSupplierApi.buyerHolds(token, cursor)),
  })
  const next = query.data?.next_cursor
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t(role === 'seller' ? 'holds.sellerTitle' : 'holds.buyerTitle')}</Typography.Title>
      <Typography.Text type="secondary">{t('holds.help')}</Typography.Text>
      {query.error ? <LoadFailure scope={role === 'seller' ? 'sell' : 'market'} error={query.error} title={errorText(query.error)} /> : null}
      <Table<HoldRow> size="small" rowKey={(h) => `${h.subscription_id}/${h.leaf_member_id}/${h.node_pool_ref}/${h.reason}/${h.since}`}
        loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={false} scroll={{ x: 900 }}
        locale={{ emptyText: t('holds.empty') }}
        columns={[
          { title: t('holds.subscription'), key: 'sub', render: (_: unknown, h) => <Space size={4} wrap>
            <Short value={h.subscription_id} />
            {h.relation ? <Tag>{t(`common.${h.relation}`)}</Tag> : null}
            {h.buyer_name ? <span>{h.buyer_name}</span> : null}
            {h.downstream_ref ? <Typography.Text code>{h.downstream_ref}</Typography.Text> : null}
            {h.via_name ? <Typography.Text type="secondary">{t('common.via', { name: h.via_name })}</Typography.Text> : null}
          </Space> },
          { title: t('holds.slot'), key: 'slot', render: (_: unknown, h) => <Typography.Text code>{h.node_pool_ref}</Typography.Text> },
          { title: t('holds.reason'), key: 'reason', render: (_: unknown, h) => t(`holds.reasons.${h.reason}`, { defaultValue: h.reason }) },
          { title: t('holds.action'), dataIndex: 'action', render: (v: string) => <Tag color={v === 'stop' ? 'error' : 'warning'}>{t(`holds.actions.${v}`, { defaultValue: v })}</Tag> },
          { title: t('holds.since'), dataIndex: 'since', render: time },
          { title: t('holds.resume'), dataIndex: 'resume_condition', render: (v: string) => t(`holds.resumeConditions.${v}`, { defaultValue: v || '—' }) },
        ]} />
      <Space>
        <Button disabled={!cursors.length || query.isFetching} onClick={() => setCursors(cursors.slice(0, -1))}>←</Button>
        <Button disabled={!next || query.isFetching} onClick={() => next && setCursors([...cursors, next])}>{t('common.loadMore')}</Button>
      </Space>
    </Space>
  )
}
