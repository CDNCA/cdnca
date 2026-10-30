import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../api/auth'
import {
  createSecurityIPList,
  deleteSecurityIPList,
  listSecurityIPLists,
  parseIPListEntries,
  updateSecurityIPList,
  type SecurityIPList,
  type SecurityIPListAudience,
} from '../api/securityIPLists'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/securityIPLists'
import { isIPAddress, validCIDR } from './streamForm'
import { FeedbackWhen } from '@cdnca/ui'

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

// IP 名单: the named lists WAF rule conditions
// "IP list" reference. A tenant edits its own lists and sees the platform's
// read only; the platform edits platform lists.
export default function SecurityIPListsPage() {
  const { t, i18n } = useTranslation('securityIPLists')
  const locale = i18n.resolvedLanguage ?? 'zh-CN'
  const queryClient = useQueryClient()
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const audience: SecurityIPListAudience = principal?.scope_kind === 'platform' ? 'admin' : 'tenant'
  const canManage = principal?.permissions.includes('security_policies.manage') ||
    principal?.permissions.includes('platform.admin') || false
  const [editing, setEditing] = useState<SecurityIPList | 'new' | null>(null)
  const [deleting, setDeleting] = useState<SecurityIPList | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  // SF-IPLIST-FEEDBACK-01: a refused save is shown in the open editor, not behind it.
  const [editorError, setEditorError] = useState<string | null>(null)
  const [form] = Form.useForm<ListForm>()
  const query = useQuery({
    queryKey: ['security-ip-lists', audience, principal?.scope_id],
    queryFn: () => listSecurityIPLists(accessToken ?? '', audience),
    enabled: Boolean(accessToken && principal),
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
    if (!values || !editing || !accessToken) return
    setBusy(true)
    setEditorError(null)
    try {
      const input = { name: values.name.trim(), description: (values.description ?? '').trim(), entries: parseIPListEntries(values.entries) }
      const saved = editing === 'new'
        ? await createSecurityIPList(accessToken, audience, input)
        : await updateSecurityIPList(accessToken, audience, editing, input)
      setMessage({ type: 'success', text: t('saved', { name: saved.name, revision: saved.revision }) })
      setEditing(null)
      await refresh()
    } catch (error) {
      // the draft stays; the reason is shown where it is being edited
      setEditorError(t(errorKey(error)))
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!deleting || !accessToken) return
    setBusy(true)
    try {
      await deleteSecurityIPList(accessToken, audience, deleting)
      setMessage({ type: 'success', text: t('deleted', { name: deleting.name }) })
      setDeleting(null)
      await refresh()
    } catch (error) {
      setMessage({ type: 'error', text: t(errorKey(error)) })
      setDeleting(null)
    } finally {
      setBusy(false)
    }
  }

  const columns: TableColumnsType<SecurityIPList> = [
    { title: t('columns.name'), dataIndex: 'name', key: 'name' },
    { title: t('columns.description'), dataIndex: 'description', key: 'description', ellipsis: true },
    { title: t('columns.entries'), key: 'entries', render: (_, list) => list.entries.length },
    { title: t('columns.revision'), dataIndex: 'revision', key: 'revision' },
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
          <Button size="small" type="link" danger icon={<Trash2 size={14} />} onClick={() => setDeleting(list)}>{t('actions.delete')}</Button>
        </Space>
      ) : null,
    },
  ]

  return (
    <div className="page security-ip-lists-page">
      <Typography.Title level={3}>{t('title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('description')}</Typography.Paragraph>
      {audience === 'tenant' ? <Typography.Paragraph type="secondary">{t('platformHint')}</Typography.Paragraph> : null}
      {message ? <Alert type={message.type} message={message.text} showIcon closable onClose={() => setMessage(null)} style={{ marginBottom: 12 }} /> : null}
      <Space style={{ marginBottom: 12 }}>
        <Button type="primary" icon={<Plus size={14} />} disabled={!canManage} onClick={() => openEditor('new')}>{t('actions.create')}</Button>
        <Button icon={<RefreshCw size={14} />} onClick={() => void refresh()}>{t('actions.refresh')}</Button>
      </Space>
      {query.isError ? <FeedbackWhen title={t(errorKey(query.error))} /> : null}
      <Table<SecurityIPList> rowKey="id" columns={columns} dataSource={query.data ?? []} loading={query.isLoading}
        pagination={false} locale={{ emptyText: t('empty') }} />
      <Modal open={editing !== null} title={editing === 'new' || editing === null ? t('form.createTitle') : t('form.editTitle', { name: editing.name })}
        okText={t('actions.save')} cancelText={t('actions.cancel')} confirmLoading={busy} onOk={() => void save()} onCancel={() => { setEditing(null); setEditorError(null) }} destroyOnHidden>
        {editorError ? <Alert type="error" showIcon role="alert" message={editorError} style={{ marginBottom: 12 }} /> : null}
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
      <Modal open={deleting !== null} title={t('actions.delete')} okText={t('actions.delete')} okButtonProps={{ danger: true }}
        cancelText={t('actions.cancel')} confirmLoading={busy} onOk={() => void remove()} onCancel={() => setDeleting(null)}>
        {deleting ? t('confirmDelete', { name: deleting.name }) : null}
      </Modal>
    </div>
  )
}
