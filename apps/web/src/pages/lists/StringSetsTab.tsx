import { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Select, Space, Tag, Tooltip, Typography, type TableColumnsType } from 'antd'
import { Eye, Pencil, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  deleteSecurityStringSet,
  listSecurityStringSets,
  stringSetMatchModes,
  type SecurityStringSetAudience,
  type SecurityStringSetSummary,
} from '../../api/securityStringSets'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/securityLists'
import {
  AddButton, DangerButton, DataTable, FeedbackWhen, TableToolbar, TOOLBAR_SEARCH_WIDTH, TOOLBAR_SELECT_WIDTH, useApp, useFeedback,
} from '@cdnca/ui'
import { ReferencesModal } from './ReferencesModal'
import { StringSetDrawer } from './StringSetDrawer'

/** 字符串集合 tab. */
export function StringSetsTab({ audience, accessToken, canManage }: {
  audience: SecurityStringSetAudience
  accessToken: string
  canManage: boolean
}) {
  const { t, i18n } = useTranslation('securityLists')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const { message } = useApp()
  const feedback = useFeedback()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<SecurityStringSetSummary | 'new' | null>(null)
  const [referencing, setReferencing] = useState<SecurityStringSetSummary | null>(null)
  const [mode, setMode] = useState<string>('')
  const [search, setSearch] = useState('')
  const query = useQuery({
    queryKey: ['security-string-sets', audience],
    queryFn: () => listSecurityStringSets(accessToken, audience),
    enabled: Boolean(accessToken),
    retry: false,
    refetchOnWindowFocus: false,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security-string-sets'] })
  const editable = (set: SecurityStringSetSummary) => canManage && set.platform === (audience === 'admin')
  const rows = useMemo(() => (query.data ?? []).filter((set) =>
    (!mode || set.match_mode === mode) && set.name.toLowerCase().includes(search.trim().toLowerCase())), [query.data, mode, search])

  const remove = async (set: SecurityStringSetSummary) => {
    try {
      await deleteSecurityStringSet(accessToken, audience, set)
      void message.success(t('deleted', { name: set.name }))
      await refresh()
    } catch (error) {
      if (error instanceof ApiError && error.code === 'string_set_in_use') {
        feedback.error(t('errors.inUse', { count: set.reference_count || 1 }),
          { actions: [{ label: t('actions.viewReferences'), primary: true, onClick: () => setReferencing(set) }] })
      } else if (error instanceof ApiError && error.code === 'version_conflict') {
        feedback.error(t('errors.version'), { actions: [{ label: t('actions.reload'), primary: true, onClick: () => { void refresh() } }] })
      } else {
        feedback.error(error instanceof ApiError && error.status === 403 ? t('errors.permission') : t('errors.failed'))
      }
    }
  }

  const columns: TableColumnsType<SecurityStringSetSummary> = [
    {
      title: t('columns.name'), key: 'name', render: (_, set) => (
        <div className="string-set-name">
          <span>{set.name}</span>
          {set.platform ? <Tag color="blue">{t('platform')}</Tag> : null}
          {set.description ? <Typography.Text type="secondary" className="string-set-description">{set.description}</Typography.Text> : null}
        </div>
      ),
    },
    { title: t('columns.mode'), key: 'mode', render: (_, set) => t(`mode.${set.match_mode}`) },
    { title: t('columns.case'), key: 'case', render: (_, set) => t(set.case_sensitive ? 'case.sensitive' : 'case.insensitive') },
    { title: t('columns.members'), key: 'members', align: 'right', render: (_, set) => set.entry_count.toLocaleString(locale) },
    {
      title: t('columns.usedBy'), key: 'used', render: (_, set) => set.reference_count === 0
        ? <span aria-label={t('usedByNone')}>—</span>
        : <Button type="link" size="small" onClick={() => setReferencing(set)}>{t('usedBy', { count: set.reference_count })}</Button>,
    },
    { title: t('columns.updatedAt'), key: 'updated_at', render: (_, set) => formatDateTime(set.updated_at, locale) },
    {
      title: t('columns.actions'), key: 'actions', render: (_, set) => editable(set) ? (
        <Space size={4}>
          <Button size="small" type="link" icon={<Pencil size={14} aria-hidden />} onClick={() => setEditing(set)}>{t('actions.edit')}</Button>
          {set.reference_count > 0 ? (
            // A disabled button gets no pointer events: the span carries the tooltip and keyboard focus.
            <Tooltip title={t('deleteDisabled', { count: set.reference_count })}>
              <span tabIndex={0} aria-label={t('deleteDisabled', { count: set.reference_count })}>
                <Button size="small" danger disabled icon={<Trash2 size={14} aria-hidden />}>{t('actions.delete')}</Button>
              </span>
            </Tooltip>
          ) : (
            <DangerButton size="small" icon={<Trash2 size={14} aria-hidden />} confirmTitle={t('confirmDelete', { name: set.name })}
              okText={t('actions.delete')} onConfirm={() => remove(set)}>{t('actions.delete')}</DangerButton>
          )}
        </Space>
      ) : (
        <Button size="small" type="link" icon={<Eye size={14} aria-hidden />} onClick={() => setEditing(set)}>{t('actions.view')}</Button>
      ),
    },
  ]

  const empty = (
    <div className="lists-empty">
      <Typography.Title level={5}>{t('empty.title')}</Typography.Title>
      <Typography.Paragraph>{t('empty.body')}</Typography.Paragraph>
      {canManage ? <AddButton name={t('add')} onClick={() => setEditing('new')} /> : null}
    </div>
  )

  return (
    <>
      <TableToolbar
        actions={canManage ? <AddButton name={t('add')} onClick={() => setEditing('new')} /> : null}
        filters={<>
          <Select aria-label={t('columns.mode')} style={{ width: TOOLBAR_SELECT_WIDTH }} value={mode} onChange={setMode}
            options={[{ value: '', label: t('mode.all') }, ...stringSetMatchModes.map((value) => ({ value, label: t(`mode.${value}`) }))]} />
          <Input.Search aria-label={t('search')} placeholder={t('search')} allowClear style={{ width: TOOLBAR_SEARCH_WIDTH }}
            onChange={(event) => setSearch(event.target.value)} />
        </>} />
      {query.isError ? <FeedbackWhen title={t('errors.load')} action={<Button onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <DataTable<SecurityStringSetSummary> rowKey="id" columns={columns} dataSource={rows} loading={query.isLoading} pagination={false}
        locale={{ emptyText: query.data && query.data.length === 0 ? empty : undefined }} />
      <StringSetDrawer target={editing} audience={audience} accessToken={accessToken}
        readOnly={editing !== null && editing !== 'new' && !editable(editing)} onClose={() => setEditing(null)}
        onSaved={(saved) => {
          setEditing(null)
          void message.success(t('saved', { name: saved.name, revision: saved.revision }))
          void refresh()
        }} />
      <ReferencesModal target={referencing} audience={audience} accessToken={accessToken} onClose={() => setReferencing(null)} />
    </>
  )
}
