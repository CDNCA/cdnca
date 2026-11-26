import { useEffect, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Dropdown, Empty, Form, Grid, Input, Result, Select, Space, Switch, Tag, Typography } from 'antd'
import { Tabs } from '../components/Tabs'
import { useFeedback, Table } from '@cdnca/ui'
import { EyeOff, Globe, MoreHorizontal } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { componentSources, statusPageApi, type ComponentSource, type ComponentStatus, type StatusPageComponent, type StatusPageComponentInput, type StatusPageGroup, type StatusPageSettings, type StatusPageText } from '../api/statusPage'
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

const rowsOf = (components: StatusPageComponent[]): Row[] => components.map((item) => ({ ...item, key: item.id }))

// The body the save sends. "Unsaved changes" compares this body for the draft and the saved page, so a value switched
// back to what was saved counts as unchanged.
function saveBody(settings: StatusPageSettings, groups: GroupRow[], rows: StatusPageComponentInput[]) {
  return {
    settings: { enabled: settings.enabled, title: settings.title.trim(), description: settings.description.trim(), show_logo: settings.show_logo },
    groups: groups.map(({ id, name, name_en, hidden }) => ({ id, name: name.trim(), name_en: name_en.trim(), hidden })),
    components: rows.map(({ id, name, name_en, description, source, line_group_id, node_id, group_id, manual_status, hidden }) => ({
      ...(id ? { id } : {}), name: name.trim(), name_en: name_en.trim(), description: description.trim(), source,
      ...(source === 'line_group' ? { line_group_id } : {}), ...(source === 'node' ? { node_id } : {}), ...(group_id ? { group_id } : {}),
      manual_status, hidden: !!hidden,
    })),
  }
}

const groupNameId = (id: string) => `status-group-name-${id}`
const componentNameId = (key: string) => `status-component-name-${key}`
const componentTargetId = (key: string) => `status-component-target-${key}`

function PageTab({ token, canManage }: { token: string; canManage: boolean }) {
  const { t, i18n: i18nInstance } = useTranslation('statusPage')
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  // Below 576px the three row actions fold into one "more" menu so the fixed column stops covering the name inputs.
  const compact = Grid.useBreakpoint().xs === true
  const query = useQuery({ queryKey: ['status-page'], queryFn: () => statusPageApi.get(token) })
  const [settings, setSettings] = useState<StatusPageSettings | null>(null)
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [rows, setRows] = useState<Row[]>([])
  const [savedNote, setSavedNote] = useState(false)
  // The input to focus once the row just added is rendered.
  const [focusId, setFocusId] = useState<string | null>(null)
  const dirty = Boolean(query.data && settings) &&
    JSON.stringify(saveBody(settings!, groups, rows)) !== JSON.stringify(saveBody(query.data!.settings, query.data!.groups, query.data!.components))
  useEffect(() => {
    if (!query.data || dirty) return
    setSettings(query.data.settings)
    setGroups(query.data.groups)
    setRows(rowsOf(query.data.components))
  }, [query.data, dirty])
  useEffect(() => {
    if (!focusId) return
    document.getElementById(focusId)?.focus()
    setFocusId(null)
  }, [focusId])
  const save = useMutation({
    mutationFn: () => {
      const body = saveBody(settings!, groups, rows)
      return statusPageApi.save(token, query.data!.revision, body.settings, body.groups, body.components)
    },
    onSuccess: (view) => {
      queryClient.setQueryData(['status-page'], view)
      setSettings(view.settings); setGroups(view.groups); setRows(rowsOf(view.components)); setSavedNote(true)
    },
    onError: (error) => feedback.error(statusPageErrorText(error)),
  })
  if (query.isError) {
    return <Alert type="error" showIcon message={statusPageErrorText(query.error)}
      action={<Button size="small" loading={query.isFetching} onClick={() => void query.refetch()}>{t('common:retry')}</Button>} />
  }
  if (query.isLoading || !settings) return <Card loading bordered={false} />
  const touch = () => setSavedNote(false)
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
  // Row checks, shown in place: the error text sits under its own input, which is aria-invalid and described by it
  // (the same required semantics and wiring as the incident drawer).
  const groupNameError = (group: GroupRow) => group.name.trim() ? null : t('groupNameRequired')
  const componentNameError = (row: Row) => row.name.trim() ? null : t('componentNameRequired')
  const componentTargetError = (row: Row) => row.source === 'line_group' && !row.line_group_id ? t('lineGroupRequired') : row.source === 'node' && !row.node_id ? t('nodeRequired') : null
  const fieldProps = (id: string, error: string | null) => ({
    id, 'aria-required': true, 'aria-invalid': error ? true : undefined, 'aria-describedby': error ? `${id}-error` : undefined, status: error ? 'error' as const : undefined,
  })
  const withError = (id: string, error: string | null, control: ReactNode, extra?: ReactNode) => (
    <Space direction="vertical" size={2} style={{ width: '100%' }}>
      {control}
      {error && <Typography.Text type="danger" id={`${id}-error`}>{error}</Typography.Text>}
      {extra}
    </Space>
  )
  const errorIds = [
    ...groups.filter((group) => groupNameError(group)).map((group) => groupNameId(group.id)),
    ...rows.flatMap((row) => [componentNameError(row) && componentNameId(row.key), componentTargetError(row) && componentTargetId(row.key)].filter((id): id is string => Boolean(id))),
  ]
  const submit = () => {
    // Like the incident drawer: the button stays clickable, and a save with an error goes to the first wrong input.
    if (errorIds.length) { document.getElementById(errorIds[0])?.focus(); return }
    save.mutate()
  }
  // Every row has 上移/下移/删除, so each action's accessible name carries the row's name; narrow screens fold them into one menu.
  const rowActions = (kind: 'component' | 'group', name: string, index: number, count: number, move: (delta: number) => void, remove: () => void) => {
    const target = name.trim() || t('unnamedRow', { index: index + 1 })
    const actions = [
      { key: 'up', text: t('moveUp'), label: t(`rowActions.${kind}.moveUp`, { name: target }), disabled: index === 0, danger: false, run: () => move(-1) },
      { key: 'down', text: t('moveDown'), label: t(`rowActions.${kind}.moveDown`, { name: target }), disabled: index === count - 1, danger: false, run: () => move(1) },
      { key: 'remove', text: t('remove'), label: t(`rowActions.${kind}.remove`, { name: target }), disabled: false, danger: true, run: remove },
    ]
    if (compact) {
      return <Dropdown trigger={['click']} menu={{
        items: actions.map(({ key, label, disabled, danger }) => ({ key, label, disabled, danger })),
        onClick: ({ key }) => actions.find((action) => action.key === key)?.run(),
      }}><Button type="link" size="small" icon={<MoreHorizontal size={16} aria-hidden />} aria-label={t(`rowActions.${kind}.more`, { name: target })} /></Dropdown>
    }
    return <Space size={0} wrap>{actions.map(({ key, text, label, disabled, danger, run }) => (
      <Button key={key} type="link" size="small" danger={danger} disabled={disabled} aria-label={label} onClick={run}>{text}</Button>))}</Space>
  }
  const actionsWidth = compact ? 56 : 170
  const addGroup = () => {
    const id = crypto.randomUUID()
    setGroups((current) => [...current, { id, name: '', name_en: '', hidden: false }]); setFocusId(groupNameId(id)); touch()
  }
  const addComponent = () => {
    const key = crypto.randomUUID()
    setRows((current) => [...current, { key, name: '', name_en: '', description: '', source: 'manual', manual_status: 'operational' }]); setFocusId(componentNameId(key)); touch()
  }
  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {/* The public state reads the saved page, not the draft: switching 公开状态页 on without saving keeps the page private. */}
      <div className="status-page-public-state">
        {query.data!.settings.enabled ? <>
          <Globe size={16} aria-hidden />
          <span>{t('publicUrlLabel')}</span>
          <span className="status-page-public-url" title={publicURL}>{publicURL}</span>
          <Typography.Text copyable={{ text: publicURL }} />
          <a href={statusPagePublicPath} target="_blank" rel="noreferrer">{t('openPage')}</a>
        </> : <>
          <EyeOff size={16} aria-hidden />
          <span className="status-page-public-note">{t('notPublic')}</span>
        </>}
      </div>
      <Form layout="vertical" disabled={!canManage} style={{ maxWidth: 640 }}>
        {/* No Form.Item name (the page keeps its own state), so the label is tied to the switch by htmlFor + id. */}
        <Form.Item label={t('enabled')} htmlFor="status-page-enabled">
          <Switch id="status-page-enabled" checked={settings.enabled} onChange={(enabled) => { setSettings({ ...settings, enabled }); touch() }} />
        </Form.Item>
        <Form.Item label={t('pageTitle')} extra={t('pageTitleHint')} htmlFor="status-page-title">
          <Input id="status-page-title" maxLength={64} value={settings.title} onChange={(event) => { setSettings({ ...settings, title: event.target.value }); touch() }} />
        </Form.Item>
        <Form.Item label={t('description')} htmlFor="status-page-description">
          <Input.TextArea id="status-page-description" maxLength={500} autoSize={{ minRows: 2, maxRows: 5 }} value={settings.description}
            onChange={(event) => { setSettings({ ...settings, description: event.target.value }); touch() }} />
        </Form.Item>
        <Form.Item label={t('showLogo')} htmlFor="status-page-show-logo">
          <Switch id="status-page-show-logo" checked={settings.show_logo} onChange={(show_logo) => { setSettings({ ...settings, show_logo }); touch() }} />
        </Form.Item>
      </Form>
      <Typography.Title level={5}>{t('groups')}</Typography.Title>
      <Typography.Text type="secondary">{t('groupsHint')}</Typography.Text>
      <Table<GroupRow> rowKey="id" size="small" pagination={false} dataSource={groups} scroll={{ x: 470 + actionsWidth }} locale={{ emptyText: <Empty description={t('noGroups')} /> }}
        columns={[
          { title: t('name'), width: 200, render: (_, row) => withError(groupNameId(row.id), groupNameError(row),
            <Input aria-label={t('name')} disabled={!canManage} maxLength={64} value={row.name} {...fieldProps(groupNameId(row.id), groupNameError(row))}
              onChange={(event) => updateGroup(row.id, { name: event.target.value })} />) },
          { title: t('nameEn'), width: 200, render: (_, row) => <Input aria-label={t('nameEn')} disabled={!canManage} maxLength={64} value={row.name_en} onChange={(event) => updateGroup(row.id, { name_en: event.target.value })} /> },
          { title: t('hidden'), width: 70, render: (_, row) => <Switch size="small" aria-label={t('hidden')} disabled={!canManage} checked={row.hidden} onChange={(hidden) => updateGroup(row.id, { hidden })} /> },
          { title: t('actions'), width: actionsWidth, fixed: 'right', render: (_, row, index) => canManage && rowActions('group', row.name, index, groups.length,
            (delta) => { setGroups((current) => swap(current, index, delta)); touch() }, () => removeGroup(row.id)) },
        ]} />
      {canManage && <Button disabled={groups.length >= 20} onClick={addGroup}>{t('addGroup')}</Button>}
      <Typography.Title level={5}>{t('components')}</Typography.Title>
      <Table<Row> rowKey="key" size="small" pagination={false} dataSource={rows} scroll={{ x: 1390 + actionsWidth }}
        locale={{ emptyText: <Empty description={t('noComponents')} /> }}
        columns={[
          { title: t('name'), width: 170, render: (_, row) => withError(componentNameId(row.key), componentNameError(row),
            <Input aria-label={t('name')} disabled={!canManage} maxLength={64} value={row.name} {...fieldProps(componentNameId(row.key), componentNameError(row))}
              onChange={(event) => update(row.key, { name: event.target.value })} />) },
          { title: t('nameEn'), width: 170, render: (_, row) => <Input aria-label={t('nameEn')} disabled={!canManage} maxLength={64} value={row.name_en} onChange={(event) => update(row.key, { name_en: event.target.value })} /> },
          { title: t('group'), width: 150, render: (_, row) => <Select aria-label={t('group')} allowClear disabled={!canManage} style={{ width: '100%' }} placeholder={t('noGroup')} value={row.group_id} options={groupOptions} onChange={(group_id) => update(row.key, { group_id })} /> },
          { title: t('source'), width: 170, render: (_, row) => <Select aria-label={t('source')} disabled={!canManage} style={{ width: '100%' }} value={row.source}
            options={componentSources.map((value) => ({ value, label: t(`sources.${value}`) }))}
            onChange={(source) => update(row.key, { source, line_group_id: source === 'line_group' ? row.line_group_id : undefined, node_id: source === 'node' ? row.node_id : undefined })} /> },
          { title: t('target'), width: 190, render: (_, row) => row.source === 'line_group' ? withError(componentTargetId(row.key), componentTargetError(row),
            <Select aria-label={t('lineGroup')} disabled={!canManage} style={{ width: '100%' }} value={row.line_group_id} options={lineGroups}
              {...fieldProps(componentTargetId(row.key), componentTargetError(row))} onChange={(line_group_id) => update(row.key, { line_group_id, line_group_missing: false })} />,
            row.line_group_missing && <Tag color="warning">{t('lineGroupMissing')}</Tag>) : row.source === 'node' ? withError(componentTargetId(row.key), componentTargetError(row),
            <Select aria-label={t('node')} showSearch optionFilterProp="label" disabled={!canManage} style={{ width: '100%' }} value={row.node_id} options={nodes}
              {...fieldProps(componentTargetId(row.key), componentTargetError(row))} onChange={(node_id) => update(row.key, { node_id })} />)
            : <Typography.Text type="secondary">{t(`sourceHints.${row.source}`)}</Typography.Text> },
          { title: t('autoStatus'), width: 150, render: (_, row) => autoSources.includes(row.source) && row.auto_status
            ? <Space size={4} wrap><Tag color="blue" title={t('modeAutoHint')}>{t('modeAuto')}</Tag><StatusTag status={row.auto_status} />{noteOf(row.note) && <Typography.Text type="secondary">{noteOf(row.note)}</Typography.Text>}</Space>
            : <Tag>{t('modeManual')}</Tag> },
          { title: t('manualStatus'), width: 120, render: (_, row) => <Select aria-label={t('manualStatus')} disabled={!canManage} style={{ width: '100%' }} value={row.manual_status}
            options={statuses.map((value) => ({ value, label: t(`status.${value}`) }))} onChange={(manual_status) => update(row.key, { manual_status })} /> },
          { title: t('hidden'), width: 70, render: (_, row) => <Switch size="small" aria-label={t('hidden')} disabled={!canManage} checked={!!row.hidden} onChange={(hidden) => update(row.key, { hidden })} /> },
          { title: t('currentStatus'), width: 100, render: (_, row) => row.status ? <StatusTag status={row.status} /> : '-' },
          { title: t('actions'), width: actionsWidth, fixed: 'right', render: (_, row, index) => canManage && rowActions('component', row.name, index, rows.length,
            (delta) => { setRows((current) => swap(current, index, delta)); touch() }, () => { setRows((current) => current.filter((item) => item.key !== row.key)); touch() }) },
        ]} />
      {canManage && (
        <Space wrap>
          <Button disabled={rows.length >= 50} onClick={addComponent}>{t('addComponent')}</Button>
          <Button type="primary" loading={save.isPending} disabled={!dirty} onClick={submit}>{t('save')}</Button>
          {dirty && <Typography.Text type="warning">{t('unsavedChanges')}</Typography.Text>}
          {savedNote && !dirty && <Typography.Text type="success">{t('saved')}</Typography.Text>}
          <Typography.Text type="secondary">{t('removeWarning')}</Typography.Text>
        </Space>
      )}
    </Space>
  )
}
