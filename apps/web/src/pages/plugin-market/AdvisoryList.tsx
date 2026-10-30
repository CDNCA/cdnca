import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Modal, Select, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { marketApi, type AdvisoryDisposition, type MarketAdvisory } from '../../api/market'
import { useSessionStore } from '../../auth/session'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/pluginStore'
import { useFeedback } from '@cdnca/ui'

const severityColor: Record<MarketAdvisory['severity'], string> = { critical: 'red', high: 'volcano', medium: 'orange', low: 'gold' }
const dispositions: AdvisoryDisposition[] = ['disabled', 'upgraded', 'uninstalled', 'accepted_risk', 'not_affected']

// AdvisoryList shows plugin security advisories with this access scope's
// acknowledgement. canAcknowledge comes from the page's own permission check;
// control-api enforces the same rule (marketsubscribehttp accessAdvisoryAck).
export function AdvisoryList({ items, loading, canAcknowledge }: { items: MarketAdvisory[]; loading?: boolean; canAcknowledge: boolean }) {
  const { t, i18n } = useTranslation('pluginStore')
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [target, setTarget] = useState<MarketAdvisory | null>(null)
  const [disposition, setDisposition] = useState<AdvisoryDisposition>('upgraded')
  const [note, setNote] = useState('')
  const ack = useMutation({
    mutationFn: (advisory: MarketAdvisory) => marketApi.acknowledgeAdvisory(token, advisory.id, disposition, note.trim()),
    onSuccess: () => {
      setTarget(null)
      setNote('')
      void client.invalidateQueries({ queryKey: ['marketAdvisories'] })
    },
    onError: (error) => void feedback.error(t('errors.failed', { code: error instanceof ApiError ? error.code : 'request_failed' })),
  })
  return (
    <>
      <Table<MarketAdvisory> rowKey="id" size="small" loading={loading} dataSource={items} pagination={{ pageSize: 20 }}
        locale={{ emptyText: t('advisories.empty') }} scroll={{ x: 960 }}
        expandable={{ rowExpandable: (a) => Boolean(a.body), expandedRowRender: (a) =>
          <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', marginBottom: 0 }}>{a.body}</Typography.Paragraph> }}
        columns={[
          { title: t('advisories.plugin'), dataIndex: 'plugin_id', render: (v: string, a) => <Space direction="vertical" size={0}>
            <strong>{a.title}</strong><Typography.Text type="secondary">{v}</Typography.Text></Space> },
          { title: t('advisories.severity'), dataIndex: 'severity', render: (v: MarketAdvisory['severity']) =>
            <Tag color={severityColor[v]}>{t(`advisories.severities.${v}`)}</Tag> },
          { title: t('advisories.affected'), dataIndex: 'affected_versions', render: (v: string) => <code>{v}</code> },
          { title: t('advisories.fixed'), dataIndex: 'fixed_version', render: (v: string) => v ? <code>{v}</code> : '—' },
          { title: t('advisories.action'), dataIndex: 'action', render: (v: MarketAdvisory['action']) =>
            <Tag color={v === 'notify' ? 'default' : 'red'}>{t(`advisories.actions.${v}`)}</Tag> },
          { title: t('advisories.published'), dataIndex: 'published_at', render: (v: string) => formatDateTime(v, i18n.resolvedLanguage ?? 'zh-CN') || v },
          { title: t('advisories.status'), key: 'status', fixed: 'right', render: (_: unknown, a) => a.acknowledgement
            ? <Tag color="green">{t('advisories.handled', { disposition: t(`advisories.dispositions.${a.acknowledgement.disposition}`,
              { defaultValue: a.acknowledgement.disposition }) })}</Tag>
            : <Space size={4}><Tag color="red">{t('advisories.pending')}</Tag>
              {canAcknowledge ? <Button size="small" onClick={() => { setTarget(a); setDisposition(a.fixed_version ? 'upgraded' : 'disabled') }}>
                {t('advisories.acknowledge')}</Button> : null}</Space> },
        ]} />
      <Modal open={!!target} title={target?.title} onCancel={() => setTarget(null)} confirmLoading={ack.isPending}
        okText={t('advisories.acknowledge')} cancelText={t('actions.cancel')} onOk={() => target && ack.mutate(target)}>
        {target ? <Space direction="vertical" style={{ width: '100%' }}>
          <Alert type={target.action === 'notify' ? 'info' : 'warning'} showIcon message={t(`advisories.actions.${target.action}`)}
            description={target.fixed_version ? `${t('advisories.fixed')}: ${target.fixed_version}` : undefined} />
          <Select<AdvisoryDisposition> value={disposition} onChange={setDisposition} aria-label={t('advisories.dispositionLabel')} style={{ width: '100%' }}
            options={dispositions.map((value) => ({ value, label: t(`advisories.dispositions.${value}`) }))} />
          <Input.TextArea rows={3} maxLength={500} aria-label={t('advisories.note')} placeholder={t('advisories.note')}
            value={note} onChange={(e) => setNote(e.target.value)} />
        </Space> : null}
      </Modal>
    </>
  )
}
