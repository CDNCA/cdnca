import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Empty, Form, Input, Result, Select, Space, Switch, Table, Tabs, Tag, Typography } from 'antd'
import { useFeedback } from '@cdnca/ui'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { componentSources, statusPageApi, type ComponentSource, type ComponentStatus, type StatusPageComponentInput, type StatusPageGroup, type StatusPageSettings, type StatusPageText } from '../api/statusPage'
import { useSessionStore } from '../auth/session'
import i18n from '../i18n'
import '../i18n/statusPage'
import { StatusPageIncidents } from './StatusPageIncidents'

// 状态页：系统 → 状态页。
// 「页面与组件」整体按修订号保存；「事件与维护」逐条发布。

export const statusPageReadPermission = 'system_configuration.read'
export const statusPageManagePermission = 'system_configuration.manage'
export const statusPagePublicPath = '/status/'
const tm = (key: string) => i18n.t(key, { ns: 'statusPage' })
const statusColor: Record<ComponentStatus, string> = { operational: 'success', degraded: 'warning', outage: 'error', maintenance: 'processing', unconfigured: 'default' }
const statuses: ComponentStatus[] = ['operational', 'degraded', 'outage', 'maintenance']

export function statusPageErrorText(error: unknown): string {
  if (error instanceof ApiError && error.code) {
    const key = `errors.${error.code}`
    if (i18n.exists(key, { ns: 'statusPage' })) return tm(key)
  }
  return tm('errors.fallback')
}

export function StatusTag({ status }: { status: ComponentStatus }) {
  const { t } = useTranslation('statusPage')
  return <Tag color={statusColor[status]}>{t(`status.${status}`)}</Tag>
}

function hasPermission(principal: Principal, permission: string) {
  return principal.permissions.includes(permission) || principal.permissions.includes('platform.admin')
}

type Row = StatusPageComponentInput & { key: string; auto_status?: ComponentStatus; status?: ComponentStatus; line_group_missing?: boolean; note?: StatusPageText }
type GroupRow = StatusPageGroup

const autoSources: ComponentSource[] = ['line_group', 'node', 'node_overall', 'gateway', 'control_api', 'web_console', 'dns_sync', 'cert_issue']

export default function StatusPageEditorPage() {
  const { t } = useTranslation('statusPage')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  if (!accessToken || !principal) return null
  if (principal.scope_kind !== 'platform' || !hasPermission(principal, statusPageReadPermission)) {
    return <Result status="403" title="403" subTitle={t('noPermission')} />
  }
  const canManage = hasPermission(principal, statusPageManagePermission)
  return (
    <Card title={t('title')}>
      <Typography.Paragraph type="secondary">{t('intro')}</Typography.Paragraph>
      <Tabs items={[
        { key: 'page', label: t('tabPage'), children: <PageTab token={accessToken} canManage={canManage} /> },
        { key: 'incidents', label: t('tabIncidents'), children: <StatusPageIncidents token={accessToken} canManage={canManage} /> },
      ]} />
    </Card>
  )
}

function swap<T>(list: T[], index: number, delta: number): T[] {
  const next = [...list]
  ;[next[index], next[index + delta]] = [next[index + delta], next[index]]
  return next
}

function PageTab({ token, canManage }: { token: string; canManage: boolean }) {
  const { t, i18n: i18nInstance } = useTranslation('statusPage')
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const query = useQuery({ queryKey: ['status-page'], queryFn: () => statusPageApi.get(token) })
  const [settings, setSettings] = useState<StatusPageSettings | null>(null)
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [rows, setRows] = useState<Row[]>([])
  const [changed, setChanged] = useState(false)
  const [savedNote, setSavedNote] = useState(false)
  useEffect(() => {
    if (!query.data || changed) return
    setSettings(query.data.settings)
    setGroups(query.data.groups)
    setRows(query.data.components.map((item) => ({ ...item, key: item.id })))
  }, [query.data, changed])
  const save = useMutation({
    mutationFn: () => statusPageApi.save(token, query.data!.revision, settings!,
      groups.map(({ id, name, name_en, hidden }) => ({ id, name: name.trim(), name_en: name_en.trim(), hidden })),
      rows.map(({ id, name, name_en, description, source, line_group_id, node_id, group_id, manual_status, hidden }) => ({
        ...(id ? { id } : {}), name: name.trim(), name_en: name_en.trim(), description: description.trim(), source,
        ...(source === 'line_group' ? { line_group_id } : {}), ...(source === 'node' ? { node_id } : {}), ...(group_id ? { group_id } : {}),
        manual_status, hidden: !!hidden,
      }))),
    onSuccess: (view) => { queryClient.setQueryData(['status-page'], view); setChanged(false); setSavedNote(true) },
    onError: (error) => feedback.error(statusPageErrorText(error)),
  })
  if (query.isLoading || !settings) return <Card loading bordered={false} />
  if (query.isError) return <Alert type="error" showIcon message={statusPageErrorText(query.error)} />
  const touch = () => { setChanged(true); setSavedNote(false) }
  const update = (key: string, patch: Partial<Row>) => { setRows((current) => current.map((row) => row.key === key ? { ...row, ...patch } : row)); touch() }
  const updateGroup = (id: string, patch: Partial<GroupRow>) => { setGroups((current) => current.map((group) => group.id === id ? { ...group, ...patch } : group)); touch() }
  const removeGroup = (id: string) => {
    setGroups((current) => current.filter((group) => group.id !== id))
    setRows((current) => current.map((row) => row.group_id === id ? { ...row, group_id: undefined } : row))
    touch()
  }
  const publicURL = `${window.location.origin}${statusPagePublicPath}`
  const lineGroups = query.data!.line_groups.map((group) => ({ value: group.id, label: group.name }))
  const nodes = query.data!.nodes.map((node) => ({ value: node.id, label: node.name }))
  const groupOptions = groups.map((group) => ({ value: group.id, label: group.name || '-' }))
  const noteOf = (note?: StatusPageText) => (i18nInstance.language.startsWith('en') ? note?.en || note?.zh : note?.zh) ?? ''
  const invalid = rows.some((row) => !row.name.trim() || (row.source === 'line_group' && !row.line_group_id) || (row.source === 'node' && !row.node_id)) ||
    groups.some((group) => !group.name.trim())
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Alert type={settings.enabled ? 'info' : 'warning'} showIcon message={
        <Space wrap>
          <span>{t('publicUrlLabel')}</span><Typography.Text copyable={{ text: publicURL }}>{publicURL}</Typography.Text>
          <a href={statusPagePublicPath} target="_blank" rel="noreferrer">{t('openPage')}</a>
          {!settings.enabled && <span>{t('notPublic')}</span>}
        </Space>
      } />
      <Form layout="vertical" disabled={!canManage} style={{ maxWidth: 640 }}>
        <Form.Item label={t('enabled')}>
          <Switch checked={settings.enabled} onChange={(enabled) => { setSettings({ ...settings, enabled }); touch() }} />
        </Form.Item>
        <Form.Item label={t('pageTitle')} extra={t('pageTitleHint')}>
          <Input maxLength={64} value={settings.title} onChange={(event) => { setSettings({ ...settings, title: event.target.value }); touch() }} />
        </Form.Item>
        <Form.Item label={t('description')}>
          <Input.TextArea maxLength={500} autoSize={{ minRows: 2, maxRows: 5 }} value={settings.description}
            onChange={(event) => { setSettings({ ...settings, description: event.target.value }); touch() }} />
        </Form.Item>
        <Form.Item label={t('showLogo')}>
          <Switch checked={settings.show_logo} onChange={(show_logo) => { setSettings({ ...settings, show_logo }); touch() }} />
        </Form.Item>
      </Form>
      <Typography.Title level={5}>{t('groups')}</Typography.Title>
      <Typography.Text type="secondary">{t('groupsHint')}</Typography.Text>
      <Table<GroupRow> rowKey="id" size="small" pagination={false} dataSource={groups} scroll={{ x: 640 }} locale={{ emptyText: <Empty description={t('noGroups')} /> }}
        columns={[
          { title: t('name'), width: 200, render: (_, row) => <Input aria-label={t('name')} disabled={!canManage} maxLength={64} status={row.name.trim() ? undefined : 'error'} value={row.name} onChange={(event) => updateGroup(row.id, { name: event.target.value })} /> },
          { title: t('nameEn'), width: 200, render: (_, row) => <Input aria-label={t('nameEn')} disabled={!canManage} maxLength={64} value={row.name_en} onChange={(event) => updateGroup(row.id, { name_en: event.target.value })} /> },
          { title: t('hidden'), width: 70, render: (_, row) => <Switch size="small" aria-label={t('hidden')} disabled={!canManage} checked={row.hidden} onChange={(hidden) => updateGroup(row.id, { hidden })} /> },
          { title: t('actions'), width: 170, fixed: 'right', render: (_, row, index) => canManage && (
            <Space size={0} wrap>
              <Button type="link" size="small" disabled={index === 0} onClick={() => { setGroups((current) => swap(current, index, -1)); touch() }}>{t('moveUp')}</Button>
              <Button type="link" size="small" disabled={index === groups.length - 1} onClick={() => { setGroups((current) => swap(current, index, 1)); touch() }}>{t('moveDown')}</Button>
              <Button type="link" size="small" danger onClick={() => removeGroup(row.id)}>{t('remove')}</Button>
            </Space>) },
        ]} />
      {canManage && <Button disabled={groups.length >= 20} onClick={() => { setGroups((current) => [...current, { id: crypto.randomUUID(), name: '', name_en: '', hidden: false }]); touch() }}>{t('addGroup')}</Button>}
      <Typography.Title level={5}>{t('components')}</Typography.Title>
      <Table<Row> rowKey="key" size="small" pagination={false} dataSource={rows} scroll={{ x: 1560 }}
        locale={{ emptyText: <Empty description={t('noComponents')} /> }}
        columns={[
          { title: t('name'), width: 170, render: (_, row) => <Input aria-label={t('name')} disabled={!canManage} maxLength={64} status={row.name.trim() ? undefined : 'error'} value={row.name} onChange={(event) => update(row.key, { name: event.target.value })} /> },
          { title: t('nameEn'), width: 170, render: (_, row) => <Input aria-label={t('nameEn')} disabled={!canManage} maxLength={64} value={row.name_en} onChange={(event) => update(row.key, { name_en: event.target.value })} /> },
          { title: t('group'), width: 150, render: (_, row) => <Select aria-label={t('group')} allowClear disabled={!canManage} style={{ width: '100%' }} placeholder={t('noGroup')} value={row.group_id} options={groupOptions} onChange={(group_id) => update(row.key, { group_id })} /> },
          { title: t('source'), width: 170, render: (_, row) => <Select aria-label={t('source')} disabled={!canManage} style={{ width: '100%' }} value={row.source}
            options={componentSources.map((value) => ({ value, label: t(`sources.${value}`) }))}
            onChange={(source) => update(row.key, { source, line_group_id: source === 'line_group' ? row.line_group_id : undefined, node_id: source === 'node' ? row.node_id : undefined })} /> },
          { title: t('target'), width: 190, render: (_, row) => row.source === 'line_group' ? (
            <Space direction="vertical" size={2} style={{ width: '100%' }}>
              <Select aria-label={t('lineGroup')} disabled={!canManage} style={{ width: '100%' }} value={row.line_group_id} options={lineGroups}
                status={row.line_group_id ? undefined : 'error'} onChange={(line_group_id) => update(row.key, { line_group_id, line_group_missing: false })} />
              {row.line_group_missing && <Tag color="warning">{t('lineGroupMissing')}</Tag>}
            </Space>) : row.source === 'node' ? (
            <Select aria-label={t('node')} showSearch optionFilterProp="label" disabled={!canManage} style={{ width: '100%' }} value={row.node_id} options={nodes}
              status={row.node_id ? undefined : 'error'} onChange={(node_id) => update(row.key, { node_id })} />) : <Typography.Text type="secondary">{t(`sourceHints.${row.source}`)}</Typography.Text> },
          { title: t('autoStatus'), width: 150, render: (_, row) => autoSources.includes(row.source) && row.auto_status
            ? <Space size={4} wrap><Tag color="blue" title={t('modeAutoHint')}>{t('modeAuto')}</Tag><StatusTag status={row.auto_status} />{noteOf(row.note) && <Typography.Text type="secondary">{noteOf(row.note)}</Typography.Text>}</Space>
            : <Tag>{t('modeManual')}</Tag> },
          { title: t('manualStatus'), width: 120, render: (_, row) => <Select aria-label={t('manualStatus')} disabled={!canManage} style={{ width: '100%' }} value={row.manual_status}
            options={statuses.map((value) => ({ value, label: t(`status.${value}`) }))} onChange={(manual_status) => update(row.key, { manual_status })} /> },
          { title: t('hidden'), width: 70, render: (_, row) => <Switch size="small" aria-label={t('hidden')} disabled={!canManage} checked={!!row.hidden} onChange={(hidden) => update(row.key, { hidden })} /> },
          { title: t('currentStatus'), width: 100, render: (_, row) => row.status ? <StatusTag status={row.status} /> : '-' },
          { title: t('actions'), width: 170, fixed: 'right', render: (_, row, index) => canManage && (
            <Space size={0} wrap>
              <Button type="link" size="small" disabled={index === 0} onClick={() => { setRows((current) => swap(current, index, -1)); touch() }}>{t('moveUp')}</Button>
              <Button type="link" size="small" disabled={index === rows.length - 1} onClick={() => { setRows((current) => swap(current, index, 1)); touch() }}>{t('moveDown')}</Button>
              <Button type="link" size="small" danger onClick={() => { setRows((current) => current.filter((item) => item.key !== row.key)); touch() }}>{t('remove')}</Button>
            </Space>) },
        ]} />
      {canManage && (
        <Space wrap>
          <Button disabled={rows.length >= 50} onClick={() => {
            setRows((current) => [...current, { key: crypto.randomUUID(), name: '', name_en: '', description: '', source: 'manual', manual_status: 'operational' }]); touch()
          }}>{t('addComponent')}</Button>
          <Button type="primary" loading={save.isPending} disabled={!changed || invalid} onClick={() => save.mutate()}>{t('save')}</Button>
          {changed && <Typography.Text type="warning">{t('unsavedChanges')}</Typography.Text>}
          {savedNote && !changed && <Typography.Text type="success">{t('saved')}</Typography.Text>}
          <Typography.Text type="secondary">{t('removeWarning')}</Typography.Text>
        </Space>
      )}
    </Space>
  )
}
