import { useState, type KeyboardEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, DatePicker, Drawer, Empty, Form, Grid, Input, Modal, Select, Space, Tag, theme } from 'antd'
import type { Dayjs } from 'dayjs'
import { useFeedback, Table } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { incidentStatuses, statusPageApi, type IncidentKind, type IncidentStatus, type StatusPageIncident } from '../api/statusPage'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/statusPage'
import { statusPageErrorText } from './StatusPageEditorPage'
import './StatusPageIncidents.css'

const impactColor = { degraded: 'warning', outage: 'error', maintenance: 'processing' } as const

interface DraftIncident { kind: IncidentKind; title: string; impact: 'degraded' | 'outage' | 'maintenance'; status: IncidentStatus; message: string; component_ids: string[]; start: Dayjs | null; end: Dayjs | null }

// The drawers keep their values in component state (no Form.Item name), so each label is tied to its control by htmlFor + a fixed id.
const ids = {
  incidentTitle: 'status-incident-title', impact: 'status-incident-impact', windowStart: 'status-incident-window-start', windowEnd: 'status-incident-window-end',
  status: 'status-incident-status', affected: 'status-incident-affected', incidentMessage: 'status-incident-message',
  updateStatus: 'status-update-status', updateMessage: 'status-update-message',
}

export function StatusPageIncidents({ token, canManage }: { token: string; canManage: boolean }) {
  const { t } = useTranslation('statusPage')
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  // Below 576px the range picker's popup (calendar and time columns side by side, about 457px) is wider than the screen:
  // the window becomes two stacked single pickers.
  const compact = Grid.useBreakpoint().xs === true
  const query = useQuery({ queryKey: ['status-page'], queryFn: () => statusPageApi.get(token) })
  const [draft, setDraft] = useState<DraftIncident | null>(null)
  const [updating, setUpdating] = useState<{ incident: StatusPageIncident; status: IncidentStatus; message: string } | null>(null)
  // Set when a submit is tried with a required field empty: the empty fields then show their error.
  const [draftTried, setDraftTried] = useState(false)
  const [updateTried, setUpdateTried] = useState(false)
  // An open date popup takes Escape for itself: the key closes the popup and stops there, so the drawer and its draft stay.
  const [pickerOpen, setPickerOpen] = useState(false)
  const pickerEscape = {
    onOpenChange: setPickerOpen,
    onKeyDown: (event: KeyboardEvent) => { if (event.key === 'Escape' && pickerOpen) event.stopPropagation() },
  }
  // The required star is decoration: aria-hidden keeps it out of the label's accessible name (the control carries
  // aria-required). A custom requiredMark also stops antd drawing its own ::before star, which screen readers read.
  const { token: themeToken } = theme.useToken()
  const requiredMark = (label: ReactNode, { required }: { required: boolean }) => required ? (
    <><span aria-hidden="true" style={{ display: 'inline-block', marginInlineEnd: themeToken.marginXXS, color: themeToken.colorError, fontSize: themeToken.fontSize,
      fontFamily: 'SimSun, sans-serif', lineHeight: 1 }}>*</span>{label}</>
  ) : label
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['status-page'] })
  const create = useMutation({
    mutationFn: (value: DraftIncident) => statusPageApi.createIncident(token, {
      kind: value.kind, title: value.title.trim(), impact: value.impact, status: value.status, message: value.message.trim(),
      component_ids: value.component_ids,
      ...(value.kind === 'maintenance' && value.start && value.end ? { scheduled_start: value.start.toISOString(), scheduled_end: value.end.toISOString() } : {}),
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
  const groups = query.data?.groups ?? []
  const names = new Map<string, string>([...groups, ...components].map((item) => [item.id, item.name]))
  const open = (kind: IncidentKind) => {
    setDraftTried(false)
    setDraft({ kind, title: '', impact: kind === 'maintenance' ? 'maintenance' : 'degraded', status: incidentStatuses[kind][0], message: '', component_ids: [], start: null, end: null })
  }
  // The maintenance window problem, if any: a missing start, a missing end, or an end not after the start (the API's rule).
  const windowError = draft?.kind === 'maintenance' ? (!draft.start ? 'start' : !draft.end ? 'end' : !draft.end.isAfter(draft.start) ? 'order' : null) : null
  const draftValid = draft && draft.title.trim() && draft.message.trim() && !windowError
  const requiredError = (show: boolean, id: string, text: string = t('required')) => show ? { validateStatus: 'error' as const, help: <span id={`${id}-error`}>{text}</span> } : {}
  const windowText = windowError === 'order' ? t('windowOrder') : undefined
  const requiredAria = (show: boolean, id: string, hintId?: string) => ({
    'aria-required': true, 'aria-invalid': show || undefined,
    'aria-describedby': [hintId, show ? `${id}-error` : undefined].filter(Boolean).join(' ') || undefined,
  })
  const submitDraft = () => {
    if (!draft) return
    if (draftValid) { create.mutate(draft); return }
    setDraftTried(true)
    document.getElementById(!draft.title.trim() ? ids.incidentTitle : windowError ? (compact && windowError !== 'start' ? ids.windowEnd : ids.windowStart) : ids.incidentMessage)?.focus()
  }
  const submitUpdate = () => {
    if (!updating) return
    if (updating.message.trim()) { post.mutate(updating); return }
    setUpdateTried(true)
    document.getElementById(ids.updateMessage)?.focus()
  }
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
                onClick={() => { setUpdateTried(false); setUpdating({ incident: row, status: row.status, message: '' }) }}>{t('postUpdate')}</Button>
              <Button type="link" size="small" danger onClick={() => remove(row)}>{t('deleteIncident')}</Button>
            </Space>) },
        ]} />
      <Drawer open={Boolean(draft)} width={520} title={draft?.kind === 'maintenance' ? t('newMaintenance') : t('newIncident')} onClose={() => setDraft(null)}
        extra={<Button type="primary" loading={create.isPending} onClick={submitDraft}>{t('submit')}</Button>}>
        {draft && (
          <Form layout="vertical" requiredMark={requiredMark}>
            <Form.Item label={t('incidentTitle')} htmlFor={ids.incidentTitle} required {...requiredError(draftTried && !draft.title.trim(), ids.incidentTitle)}>
              <Input id={ids.incidentTitle} maxLength={120} value={draft.title} {...requiredAria(draftTried && !draft.title.trim(), ids.incidentTitle)}
                onChange={(event) => setDraft({ ...draft, title: event.target.value })} />
            </Form.Item>
            {draft.kind === 'incident' ? (
              <Form.Item label={t('incidentImpact')} htmlFor={ids.impact} required>
                <Select id={ids.impact} aria-required value={draft.impact} onChange={(impact) => setDraft({ ...draft, impact })}
                  options={(['degraded', 'outage'] as const).map((value) => ({ value, label: t(`impact.${value}`) }))} />
              </Form.Item>
            ) : compact ? (
              <>
                {/* One calendar per popup, its time columns stacked under it (status-window-picker-popup), so it fits a 390px screen. */}
                <Form.Item label={t('windowStart')} htmlFor={ids.windowStart} required {...requiredError(draftTried && windowError === 'start', ids.windowStart)}>
                  <DatePicker id={ids.windowStart} showTime style={{ width: '100%' }} classNames={{ popup: { root: 'status-window-picker-popup status-window-picker-sheet' } }} value={draft.start} {...pickerEscape}
                    {...requiredAria(draftTried && windowError === 'start', ids.windowStart)} onChange={(start) => setDraft({ ...draft, start })} />
                </Form.Item>
                <Form.Item label={t('windowEnd')} htmlFor={ids.windowEnd} required
                  {...requiredError(draftTried && (windowError === 'end' || windowError === 'order'), ids.windowEnd, windowText)}>
                  <DatePicker id={ids.windowEnd} showTime style={{ width: '100%' }} classNames={{ popup: { root: 'status-window-picker-popup status-window-picker-sheet' } }} value={draft.end} {...pickerEscape}
                    {...requiredAria(draftTried && (windowError === 'end' || windowError === 'order'), ids.windowEnd)} onChange={(end) => setDraft({ ...draft, end })} />
                </Form.Item>
              </>
            ) : (
              <Form.Item label={t('window')} htmlFor={ids.windowStart} required {...requiredError(draftTried && Boolean(windowError), ids.windowStart, windowText)}>
                {/* The range picker has two inputs: the field label names the start input, this hidden label names the end input. */}
                <label htmlFor={ids.windowEnd} className="visually-hidden">{t('windowEnd')}</label>
                <DatePicker.RangePicker id={{ start: ids.windowStart, end: ids.windowEnd }} showTime style={{ width: '100%' }} {...pickerEscape}
                  value={draft.start && draft.end ? [draft.start, draft.end] : null}
                  {...requiredAria(draftTried && Boolean(windowError), ids.windowStart)}
                  onChange={(value) => setDraft({ ...draft, start: value?.[0] && value[1] ? value[0] : null, end: value?.[0] && value[1] ? value[1] : null })} />
              </Form.Item>
            )}
            <Form.Item label={t('incidentState')} htmlFor={ids.status} required>
              <Select id={ids.status} aria-required value={draft.status} onChange={(status) => setDraft({ ...draft, status })}
                options={incidentStatuses[draft.kind].map((value) => ({ value, label: t(`incidentStatus.${value}`) }))} />
            </Form.Item>
            <Form.Item label={t('affected')} htmlFor={ids.affected}>
              <Select id={ids.affected} mode="multiple" value={draft.component_ids} onChange={(component_ids) => setDraft({ ...draft, component_ids })}
                options={[...groups.map((item) => ({ value: item.id, label: `${item.name} (${t('group')})` })), ...components.map((item) => ({ value: item.id, label: item.name }))]} />
            </Form.Item>
            <Form.Item label={t('message')} htmlFor={ids.incidentMessage} extra={<span id={`${ids.incidentMessage}-hint`}>{t('messageHint')}</span>} required
              {...requiredError(draftTried && !draft.message.trim(), ids.incidentMessage)}>
              <Input.TextArea id={ids.incidentMessage} maxLength={2000} autoSize={{ minRows: 3, maxRows: 8 }} value={draft.message}
                {...requiredAria(draftTried && !draft.message.trim(), ids.incidentMessage, `${ids.incidentMessage}-hint`)}
                onChange={(event) => setDraft({ ...draft, message: event.target.value })} />
            </Form.Item>
          </Form>
        )}
      </Drawer>
      <Drawer open={Boolean(updating)} width={520} title={`${t('postUpdate')} · ${updating?.incident.title ?? ''}`} onClose={() => setUpdating(null)}
        extra={<Button type="primary" loading={post.isPending} onClick={submitUpdate}>{t('submit')}</Button>}>
        {updating && (
          <Form layout="vertical" requiredMark={requiredMark}>
            <Form.Item label={t('incidentState')} htmlFor={ids.updateStatus} required>
              <Select id={ids.updateStatus} aria-required value={updating.status} onChange={(status) => setUpdating({ ...updating, status })}
                options={incidentStatuses[updating.incident.kind].map((value) => ({ value, label: t(`incidentStatus.${value}`) }))} />
            </Form.Item>
            <Form.Item label={t('message')} htmlFor={ids.updateMessage} extra={<span id={`${ids.updateMessage}-hint`}>{t('messageHint')}</span>} required
              {...requiredError(updateTried && !updating.message.trim(), ids.updateMessage)}>
              <Input.TextArea id={ids.updateMessage} maxLength={2000} autoSize={{ minRows: 3, maxRows: 8 }} value={updating.message}
                {...requiredAria(updateTried && !updating.message.trim(), ids.updateMessage, `${ids.updateMessage}-hint`)}
                onChange={(event) => setUpdating({ ...updating, message: event.target.value })} />
            </Form.Item>
          </Form>
        )}
      </Drawer>
    </Space>
  )
}
