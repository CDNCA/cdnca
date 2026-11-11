import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Form, Input, Modal, Space, Tag, Tooltip, type TableColumnsType } from 'antd'
import { Pencil, RefreshCw, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  createSecurityIPList,
  deleteSecurityIPList,
  listSecurityIPLists,
  parseIPListEntries,
  updateSecurityIPList,
  type SecurityIPList,
  type SecurityIPListAudience,
} from '../../api/securityIPLists'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/securityIPLists'
import '../../i18n/securityLists'
import { isIPAddress, validCIDR } from '../streamForm'
import { AddButton, DangerButton, DataTable, FeedbackWhen, InlineNotice, ModalFooter, TableToolbar, useApp, useFeedback } from '@cdnca/ui'

interface ListForm {
  name: string
  description: string
  entries: string
}

function errorKey(error: unknown): string {
  if (!(error instanceof ApiError)) return 'errors.failed'
  switch (error.code) {
    case 'validation_error': return 'errors.invalid'
    case 'ip_list_name_conflict': return 'errors.nameConflict'
    case 'version_conflict': return 'errors.version'
    case 'ip_list_in_use': return 'errors.inUse'
    case 'ip_list_limit': return 'errors.limit'
    case 'ip_list_not_found': return 'errors.notFound'
  }
  return error.status === 403 ? 'errors.permission' : 'errors.failed'
}

// IP 名单 tab of 列表与对象: the named lists
// WAF rule conditions "IP list" reference. A tenant edits its own lists and
// sees the platform's read only; the platform edits platform lists.
export function IPListsTab({ audience, accessToken, canManage, scopeID }: {
  audience: SecurityIPListAudience
  accessToken: string
  canManage: boolean
  scopeID?: string
}) {
  const { t, i18n } = useTranslation('securityIPLists')
  const { t: tl } = useTranslation('securityLists')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const { message } = useApp()
  const feedback = useFeedback()
  const [editing, setEditing] = useState<SecurityIPList | 'new' | null>(null)
  const [busy, setBusy] = useState(false)
  // SF-IPLIST-FEEDBACK-01: a refused save is shown in the open editor, not behind it.
  const [editorError, setEditorError] = useState<string | null>(null)
  const [form] = Form.useForm<ListForm>()
  const query = useQuery({
    queryKey: ['security-ip-lists', audience, scopeID],
    queryFn: () => listSecurityIPLists(accessToken, audience),
    enabled: Boolean(accessToken),
    retry: false,
    refetchOnWindowFocus: false,
  })
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['security-ip-lists'] })
  const editable = (list: SecurityIPList) => canManage && list.platform === (audience === 'admin')

  const openEditor = (target: SecurityIPList | 'new') => {
    setEditing(target)
    setEditorError(null)
    form.setFieldsValue(target === 'new' ? { name: '', description: '', entries: '' }
      : { name: target.name, description: target.description, entries: target.entries.join('\n') })
  }

  const save = async () => {
    const values = await form.validateFields().catch(() => null)
    if (!values || !editing) return
    setBusy(true)
    setEditorError(null)
    try {
      const input = { name: values.name.trim(), description: (values.description ?? '').trim(), entries: parseIPListEntries(values.entries) }
      const saved = editing === 'new'
        ? await createSecurityIPList(accessToken, audience, input)
        : await updateSecurityIPList(accessToken, audience, editing, input)
      void message.success(t('saved', { name: saved.name, revision: saved.revision }))
      setEditing(null)
      await refresh()
    } catch (error) {
      // the draft stays; the reason is shown where it is being edited
      setEditorError(t(errorKey(error)))
    } finally {
      setBusy(false)
    }
  }

  const remove = async (list: SecurityIPList) => {
    try {
      await deleteSecurityIPList(accessToken, audience, list)
      void message.success(t('deleted', { name: list.name }))
      await refresh()
    } catch (error) {
      // An event error: a dialog (COMPONENTS.md), not an in-page Alert.
      feedback.error(t(errorKey(error)))
    }
  }

  const columns: TableColumnsType<SecurityIPList> = [
    { title: t('columns.name'), dataIndex: 'name', key: 'name' },
    { title: t('columns.description'), dataIndex: 'description', key: 'description', ellipsis: true },
    { title: t('columns.entries'), key: 'entries', render: (_, list) => list.entries.length },
    {
      title: tl('columns.usedBy'), key: 'used',
      render: (_, list) => (list.reference_count ?? 0) === 0 ? <span aria-label={tl('usedByNone')}>—</span> : tl('usedBy', { count: list.reference_count }),
    },
    {
      title: t('columns.owner'), key: 'owner',
      render: (_, list) => <Tag color={list.platform ? 'blue' : 'default'}>{t(list.platform ? 'owner.platform' : 'owner.own')}</Tag>,
    },
    { title: t('columns.updatedAt'), key: 'updated_at', render: (_, list) => formatDateTime(list.updated_at, locale) },
    {
      title: t('columns.actions'), key: 'actions',
      render: (_, list) => editable(list) ? (
        <Space size={4}>
          <Button size="small" type="link" icon={<Pencil size={14} />} onClick={() => openEditor(list)}>{t('actions.edit')}</Button>
          {(list.reference_count ?? 0) > 0 ? (
            <Tooltip title={tl('deleteDisabled', { count: list.reference_count })}>
              <span tabIndex={0} aria-label={tl('deleteDisabled', { count: list.reference_count })}>
                <Button size="small" danger disabled icon={<Trash2 size={14} aria-hidden />}>{t('actions.delete')}</Button>
              </span>
            </Tooltip>
          ) : (
            <DangerButton size="small" icon={<Trash2 size={14} aria-hidden />} confirmTitle={t('confirmDelete', { name: list.name })}
              okText={t('actions.delete')} onConfirm={() => remove(list)}>{t('actions.delete')}</DangerButton>
          )}
        </Space>
      ) : null,
    },
  ]

  return (
    <>
      <TableToolbar
        actions={<>
          {canManage ? <AddButton name={tl('addIP')} onClick={() => openEditor('new')} /> : null}
          <Button icon={<RefreshCw size={14} aria-hidden />} onClick={() => void refresh()}>{t('actions.refresh')}</Button>
        </>} />
      {query.isError ? <FeedbackWhen title={t(errorKey(query.error))} action={<Button onClick={() => void query.refetch()}>{tl('actions.retry')}</Button>} /> : null}
      <DataTable<SecurityIPList> rowKey="id" columns={columns} dataSource={query.data ?? []} loading={query.isLoading}
        pagination={false} locale={{ emptyText: t('empty') }} />
      <Modal open={editing !== null} title={editing === 'new' || editing === null ? t('form.createTitle') : t('form.editTitle', { name: editing.name })}
        onCancel={() => { setEditing(null); setEditorError(null) }} destroyOnHidden
        footer={<ModalFooter onCancel={() => { setEditing(null); setEditorError(null) }} onOk={() => void save()} okText={t('actions.save')} cancelText={t('actions.cancel')} loading={busy} />}>
        <InlineNotice>{editorError}</InlineNotice>
        <Form form={form} layout="vertical">
          <Form.Item name="name" label={t('form.name')} rules={[{ required: true, whitespace: true, max: 64 }]}>
            <Input aria-label={t('form.name')} maxLength={64} />
          </Form.Item>
          <Form.Item name="description" label={t('form.description')} rules={[{ max: 512 }]}>
            <Input aria-label={t('form.description')} maxLength={512} />
          </Form.Item>
          <Form.Item name="entries" label={t('form.entries')} extra={t('form.entriesHint')} rules={[{ required: true, whitespace: true }, {
            validator: (_, value: string | undefined) => {
              const invalid = parseIPListEntries(value ?? '').filter((entry) => !isIPAddress(entry) && !validCIDR(entry))
              return invalid.length === 0 ? Promise.resolve()
                : Promise.reject(new Error(t('form.invalidEntries', { entries: invalid.slice(0, 5).join('、'), count: invalid.length })))
            },
          }]}>
            <Input.TextArea aria-label={t('form.entries')} rows={8} placeholder={t('form.entriesPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}
