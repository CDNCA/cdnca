import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, DatePicker, Drawer, Empty, Form, Input, Modal, Select, Space, Table, Tag } from 'antd'
import type { Dayjs } from 'dayjs'
import { useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { incidentStatuses, statusPageApi, type IncidentKind, type IncidentStatus, type StatusPageIncident } from '../api/statusPage'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/statusPage'
import { statusPageErrorText } from './StatusPageEditorPage'

const impactColor = { degraded: 'warning', outage: 'error', maintenance: 'processing' } as const

interface DraftIncident { kind: IncidentKind; title: string; impact: 'degraded' | 'outage' | 'maintenance'; status: IncidentStatus; message: string; component_ids: string[]; window: [Dayjs, Dayjs] | null }

export function StatusPageIncidents({ token, canManage }: { token: string; canManage: boolean }) {
  const { t } = useTranslation('statusPage')
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['status-page'], queryFn: () => statusPageApi.get(token) })
  const [draft, setDraft] = useState<DraftIncident | null>(null)
  const [updating, setUpdating] = useState<{ incident: StatusPageIncident; status: IncidentStatus; message: string } | null>(null)
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['status-page'] })
  const create = useMutation({
    mutationFn: (value: DraftIncident) => statusPageApi.createIncident(token, {
      kind: value.kind, title: value.title.trim(), impact: value.impact, status: value.status, message: value.message.trim(),
      component_ids: value.component_ids,
      ...(value.kind === 'maintenance' && value.window ? { scheduled_start: value.window[0].toISOString(), scheduled_end: value.window[1].toISOString() } : {}),
    }),
    onSuccess: () => { setDraft(null); void refresh() },
    onError: (error) => feedback.error(statusPageErrorText(error)),
  })
  const post = useMutation({
    mutationFn: (value: NonNullable<typeof updating>) => statusPageApi.addUpdate(token, value.incident.id, value.status, value.message.trim()),
    onSuccess: () => { setUpdating(null); void refresh() },
    onError: (error) => feedback.error(statusPageErrorText(error)),
  })
  const remove = (incident: StatusPageIncident) => Modal.confirm({
    title: t('deleteIncident'), content: t('deleteConfirm'), okButtonProps: { danger: true }, okText: t('deleteIncident'),
    onOk: async () => {
      try { await statusPageApi.deleteIncident(token, incident.id); await refresh() } catch (error) { feedback.error(statusPageErrorText(error)) }
    },
  })
  const components = query.data?.components ?? []
  const names = new Map(components.map((item) => [item.id, item.name]))
  const open = (kind: IncidentKind) => setDraft({
    kind, title: '', impact: kind === 'maintenance' ? 'maintenance' : 'degraded', status: incidentStatuses[kind][0], message: '', component_ids: [], window: null,
  })
  const draftValid = draft && draft.title.trim() && draft.message.trim() && (draft.kind === 'incident' || draft.window)
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {canManage && (
        <Space wrap>
          <Button type="primary" danger onClick={() => open('incident')}>{t('newIncident')}</Button>
          <Button onClick={() => open('maintenance')}>{t('newMaintenance')}</Button>
        </Space>
      )}
      <Table<StatusPageIncident> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data?.incidents ?? []} pagination={{ pageSize: 20 }}
        scroll={{ x: 960 }} locale={{ emptyText: <Empty description={t('noIncidents')} /> }}
        columns={[
          { title: t('kind.incident'), width: 80, render: (_, row) => t(`kind.${row.kind}`) },
          { title: t('incidentTitle'), dataIndex: 'title', width: 220 },
          { title: t('incidentImpact'), width: 80, render: (_, row) => <Tag color={impactColor[row.impact]}>{t(`impact.${row.impact}`)}</Tag> },
          { title: t('incidentState'), width: 90, render: (_, row) => t(`incidentStatus.${row.status}`) },
          { title: t('affected'), width: 180, render: (_, row) => row.component_ids.map((id) => names.get(id)).filter(Boolean).join(t('listSeparator')) || '-' },
          { title: t('startedAt'), width: 170, render: (_, row) => row.kind === 'maintenance' && row.scheduled_start && row.scheduled_end
            ? `${formatDateTime(row.scheduled_start)} - ${formatDateTime(row.scheduled_end)}` : formatDateTime(row.started_at) },
          { title: t('latestUpdate'), width: 240, ellipsis: true, render: (_, row) => row.updates[0]?.message ?? '-' },
          { title: t('actions'), width: 150, fixed: 'right', render: (_, row) => canManage && (
            <Space size={0}>
              <Button type="link" size="small" disabled={Boolean(row.resolved_at)} title={row.resolved_at ? t('closed') : undefined}
                onClick={() => setUpdating({ incident: row, status: row.status, message: '' })}>{t('postUpdate')}</Button>
              <Button type="link" size="small" danger onClick={() => remove(row)}>{t('deleteIncident')}</Button>
            </Space>) },
        ]} />
      <Drawer open={Boolean(draft)} width={520} title={draft?.kind === 'maintenance' ? t('newMaintenance') : t('newIncident')} onClose={() => setDraft(null)}
        extra={<Button type="primary" loading={create.isPending} disabled={!draftValid} onClick={() => draft && create.mutate(draft)}>{t('submit')}</Button>}>
        {draft && (
          <Form layout="vertical">
            <Form.Item label={t('incidentTitle')} required><Input maxLength={120} value={draft.title} onChange={(event) => setDraft({ ...draft, title: event.target.value })} /></Form.Item>
            {draft.kind === 'incident' ? (
              <Form.Item label={t('incidentImpact')} required>
                <Select value={draft.impact} onChange={(impact) => setDraft({ ...draft, impact })}
                  options={(['degraded', 'outage'] as const).map((value) => ({ value, label: t(`impact.${value}`) }))} />
              </Form.Item>
            ) : (
              <Form.Item label={t('window')} required>
                <DatePicker.RangePicker showTime style={{ width: '100%' }} value={draft.window} onChange={(value) => setDraft({ ...draft, window: value?.[0] && value[1] ? [value[0], value[1]] : null })} />
              </Form.Item>
            )}
            <Form.Item label={t('incidentState')} required>
              <Select value={draft.status} onChange={(status) => setDraft({ ...draft, status })}
                options={incidentStatuses[draft.kind].map((value) => ({ value, label: t(`incidentStatus.${value}`) }))} />
            </Form.Item>
            <Form.Item label={t('affected')}>
              <Select mode="multiple" value={draft.component_ids} onChange={(component_ids) => setDraft({ ...draft, component_ids })}
                options={components.map((item) => ({ value: item.id, label: item.name }))} />
            </Form.Item>
            <Form.Item label={t('message')} extra={t('messageHint')} required>
              <Input.TextArea maxLength={2000} autoSize={{ minRows: 3, maxRows: 8 }} value={draft.message} onChange={(event) => setDraft({ ...draft, message: event.target.value })} />
            </Form.Item>
          </Form>
        )}
      </Drawer>
      <Drawer open={Boolean(updating)} width={520} title={`${t('postUpdate')} · ${updating?.incident.title ?? ''}`} onClose={() => setUpdating(null)}
        extra={<Button type="primary" loading={post.isPending} disabled={!updating?.message.trim()} onClick={() => updating && post.mutate(updating)}>{t('submit')}</Button>}>
        {updating && (
          <Form layout="vertical">
            <Form.Item label={t('incidentState')} required>
              <Select value={updating.status} onChange={(status) => setUpdating({ ...updating, status })}
                options={incidentStatuses[updating.incident.kind].map((value) => ({ value, label: t(`incidentStatus.${value}`) }))} />
            </Form.Item>
            <Form.Item label={t('message')} extra={t('messageHint')} required>
              <Input.TextArea maxLength={2000} autoSize={{ minRows: 3, maxRows: 8 }} value={updating.message} onChange={(event) => setUpdating({ ...updating, message: event.target.value })} />
            </Form.Item>
          </Form>
        )}
      </Drawer>
    </Space>
  )
}
