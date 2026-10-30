import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Modal, Space, Spin, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { marketSupplierApi, supplierPageSize, type Complaint } from '../../../api/marketSupplier'
import { CursorPager, LoadFailure, useCursorPages } from './shared'
import { useErrorText, useTime, useToken, useWrite } from './hooks'

const stateColor: Record<string, string> = { open: 'processing', reviewing: 'processing', actioned: 'error', rejected: 'default', withdrawn: 'default' }

// ADR 0012 §18.3 (ML-17): my stop requests, their progress and outcome.
export function ComplaintsPanel() {
  const { t } = useTranslation('marketSupplier')
  const { modal } = App.useApp()
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const pages = useCursorPages()
  const query = useQuery({ queryKey: ['nodeMarket', 'complaints', pages.cursor], enabled: !!token, retry: false,
    queryFn: () => marketSupplierApi.complaints(token, pages.cursor) })
  const withdraw = useWrite((c: Complaint) => marketSupplierApi.withdrawComplaint(token, c.id), 'complaints.withdrawn')
  const [detail, setDetail] = useState<string | null>(null)
  return (
    <Space direction="vertical" style={{ width: '100%' }}>
      <Typography.Title level={5}>{t('complaints.title')}</Typography.Title>
      <Typography.Text type="secondary">{t('complaints.help')}</Typography.Text>
      {query.error ? <LoadFailure scope="sell" error={query.error} title={errorText(query.error)} /> : null}
      <Table<Complaint> size="small" rowKey="id" loading={query.isLoading} dataSource={query.data?.items ?? []} pagination={false}
        locale={{ emptyText: t('complaints.empty') }} scroll={{ x: 900 }}
        columns={[
          { title: t('complaints.target'), dataIndex: 'target_ref', render: (v: string) => <Typography.Text code>{v.length > 20 ? v.slice(0, 8) : v}</Typography.Text> },
          { title: t('complaints.category'), dataIndex: 'category', render: (v: string) => t(`complaints.categories.${v}`, { defaultValue: v }) },
          { title: t('complaints.detail'), dataIndex: 'detail', ellipsis: true },
          { title: t('complaints.state'), dataIndex: 'state', render: (v: string) => <Tag color={stateColor[v]}>{t(`complaints.stateNames.${v}`, { defaultValue: v })}</Tag> },
          { title: t('complaints.result'), dataIndex: 'action', render: (v: string | null) => (v ? t(`complaints.actionNames.${v}`, { defaultValue: v }) : '—') },
          { title: t('complaints.created'), dataIndex: 'created_at', render: time },
          { key: 'actions', render: (_: unknown, c) => <Space size={4}>
            <Button size="small" type="link" onClick={() => setDetail(c.id)}>{t('complaints.view')}</Button>
            {(c.state === 'open' || c.state === 'reviewing') ? <Button size="small" loading={withdraw.isPending}
              onClick={() => modal.confirm({ title: t('complaints.withdrawConfirm'), onOk: () => withdraw.mutateAsync(c).catch(() => undefined) })}>{t('complaints.withdraw')}</Button> : null}
          </Space> },
        ]} />
      <CursorPager pages={pages} pageSize={supplierPageSize} count={query.data?.items.length ?? 0} next={query.data?.next_cursor} busy={query.isFetching} />
      {detail ? <ComplaintDetail id={detail} onClose={() => setDetail(null)} /> : null}
    </Space>
  )
}

// GET supply-complaints/{id}: the filer's own view (outcome and its target reference only, U5).
function ComplaintDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { t } = useTranslation('marketSupplier')
  const token = useToken()
  const time = useTime()
  const errorText = useErrorText()
  const query = useQuery({ queryKey: ['nodeMarket', 'complaint', id], enabled: !!token, retry: false, queryFn: () => marketSupplierApi.complaint(token, id) })
  const c = query.data
  const evidence = c?.evidence ?? {}
  return (
    <Modal open title={t('complaints.detailTitle')} footer={null} onCancel={onClose} width={640}>
      {query.error ? <Alert type="error" showIcon message={errorText(query.error)} /> : null}
      {query.isLoading ? <Spin /> : null}
      {c ? <Descriptions column={1} size="small" bordered items={[
        { key: 'target', label: t('complaints.target'), children: <Typography.Text code copyable>{c.target_ref}</Typography.Text> },
        { key: 'category', label: t('complaints.category'), children: t(`complaints.categories.${c.category}`, { defaultValue: c.category }) },
        { key: 'state', label: t('complaints.state'), children: <Tag color={stateColor[c.state]}>{t(`complaints.stateNames.${c.state}`, { defaultValue: c.state })}</Tag> },
        { key: 'result', label: t('complaints.result'), children: c.action ? t(`complaints.actionNames.${c.action}`, { defaultValue: c.action }) : '—' },
        { key: 'detail', label: t('complaints.detail'), children: <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{c.detail}</Typography.Paragraph> },
        { key: 'domains', label: t('complaints.domainsLabel'), children: (evidence.domains ?? []).length ? (evidence.domains ?? []).join(', ') : '—' },
        { key: 'window', label: t('complaints.window'), children: evidence.from || evidence.to ? `${time(evidence.from)} ~ ${time(evidence.to)}` : '—' },
        { key: 'links', label: t('complaints.links'), children: (evidence.attachments ?? []).length ? <Space direction="vertical" size={2}>
          {(evidence.attachments ?? []).map((a) => <Typography.Text key={a.url} copyable={{ text: a.url }}>{a.name || a.url}</Typography.Text>)}</Space> : '—' },
        { key: 'created', label: t('complaints.created'), children: time(c.created_at) },
        { key: 'resolved', label: t('complaints.resolvedAt'), children: time(c.resolved_at) },
        { key: 'released', label: t('complaints.releasedAt'), children: time(c.released_at) },
      ]} /> : null}
    </Modal>
  )
}
