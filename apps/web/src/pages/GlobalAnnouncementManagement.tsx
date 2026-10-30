import { useCallback, useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Checkbox, Form, Input, InputNumber, Modal, Result, Select, Space, Switch, Table, Tag, type TableColumnsType } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown, useFormSubmitError } from '@cdnca/ui'
import { Edit3, Eye, EyeOff, Plus, RefreshCw, Send, Trash2, Undo2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  globalAnnouncementsApi,
  newAnnouncementIdempotencyKey,
  type GlobalAnnouncement,
  type AudienceDirectoryEntry,
  type GlobalAnnouncementInput,
} from '../api/announcements'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { DataState } from '../components/DataState'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import AnnouncementAudienceSelect, { AudienceCountNotice } from './AnnouncementAudienceSelect'
import { audienceEntryLabel, lookupAudienceEntries, type AudienceOption } from './announcementAudience'

type GlobalStatus = GlobalAnnouncement['status'] | 'archived'
type Editor = { item: GlobalAnnouncement | null }
type Confirm = { action: 'publish' | 'withdraw' | 'archive' | 'restore'; item: GlobalAnnouncement } | { action: 'archive-batch'; items: GlobalAnnouncement[] }
type WriteResult = GlobalAnnouncement | GlobalAnnouncement[]
type BatchProgress = { completed: string[]; total: number }
// draft: a create/update from the editor, whose refused fields are marked on it.
type WriteAttempt = { ownerKey: string; run: () => Promise<WriteResult>; key: string; batch?: BatchProgress; notice: string; draft?: boolean }

interface FormValues {
  title: string
  format: 'content' | 'link'
  body: string
  link_url: string
  sort_order: number
  visible: boolean
  popup: boolean
  red: boolean
  bold: boolean
  all_tenants: boolean
  tenant_scope_ids: AudienceOption[]
  /** Tenant whose roles and users are being searched (at most one); not sent to the API. */
  target_tenant?: AudienceOption[]
  role_targets: AudienceOption[]
  user_targets: AudienceOption[]
  withdrawal_visibility: 'retain' | 'hide'
}

function platformOwner(principal: Principal, sessionEpoch: number) {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !principal.scope_id || !principal.user_id || !sessionEpoch) return null
  return [principal.scope_kind, principal.scope_id, principal.user_id, sessionEpoch] as const
}

function currentToken(ownerKey: string) {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !principal.permissions.includes('announcements.manage')) return null
  const owner = platformOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

// Role and user targets are scoped pairs; the option value carries both.
function pairValue(scopeID: string, id: string) {
  return `${scopeID}/${id}`
}

function splitPair(value: string): [string, string] {
  const [scopeID, id] = value.split('/')
  return [scopeID, id]
}

function uniqueValues(options: AudienceOption[] | undefined) {
  return [...new Set((options ?? []).map((option) => option.value))]
}

function globalAnnouncementInput(item: GlobalAnnouncement, visible = item.visible): GlobalAnnouncementInput {
  return {
    title: item.title,
    body: item.body,
    format: item.format,
    link_url: item.link_url ?? '',
    sort_order: item.sort_order,
    visible,
    popup: item.popup,
    red: item.red,
    bold: item.bold,
    all_tenants: item.audience.all_tenants,
    tenant_scope_ids: item.audience.tenant_scope_ids,
    role_targets: item.audience.role_targets,
    user_targets: item.audience.user_targets,
    withdrawal_visibility: item.withdrawal_visibility,
  }
}

function isUnknownWrite(error: unknown) {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function batchItemIdempotencyKey(batchKey: string, itemID: string) {
  const suffix = `-${itemID.slice(-127)}`
  return `${batchKey.slice(0, Math.max(0, 128 - suffix.length))}${suffix}`
}

function errorText(error: unknown, t: (key: string) => string) {
  if (error instanceof ApiError) {
    const key: Record<string, string> = {
      permission_denied: 'errors.permissionDenied', version_conflict: 'errors.versionConflict',
      idempotency_conflict: 'errors.idempotencyConflict', empty_audience: 'errors.emptyAudience',
      audience_scope_denied: 'global.errors.targetScope', announcement_not_found: 'errors.notFound',
      announcement_state_conflict: 'errors.stateConflict', validation_error: 'errors.validation',
    }
    if (key[error.code]) return t(key[error.code])
  }
  return localizedUnknownApiError(error, t('errors.requestFailed'))
}

export default function GlobalAnnouncementManagement() {
  const { t, i18n } = useTranslation('announcements')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? platformOwner(principal, sessionEpoch) : null
  const ownerKey = owner ? JSON.stringify(owner) : ''
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [status, setStatus] = useState<GlobalStatus | 'all'>('all')
  const [cursors, setCursors] = useState<string[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [confirm, setConfirm] = useState<Confirm | null>(null)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [form] = Form.useForm<FormValues>()
  const markSubmitError = useFormSubmitError(form)
  const cursor = cursors.at(-1)
  const [editorLoadingID, setEditorLoadingID] = useState<string | null>(null)
  const targetTenant = (Form.useWatch('target_tenant', form) as AudienceOption[] | undefined)?.[0]

  const searchDirectory = useCallback((kind: 'tenant' | 'role' | 'user', scopeID?: string) => async (search: string): Promise<AudienceDirectoryEntry[]> => {
    const token = currentToken(ownerKey)
    if (!token) throw new ApiError('stale session', 401, 'permission_denied')
    const result = await globalAnnouncementsApi.audienceDirectory(token, { kind, search, scope_id: scopeID })
    if (!currentToken(ownerKey)) throw new ApiError('stale session', 401, 'permission_denied')
    return result.items
  }, [ownerKey])
  const searchTenants = useMemo(() => searchDirectory('tenant'), [searchDirectory])
  const searchRoles = useMemo(() => targetTenant ? searchDirectory('role', targetTenant.value) : null, [searchDirectory, targetTenant])
  const searchUsers = useMemo(() => targetTenant ? searchDirectory('user', targetTenant.value) : null, [searchDirectory, targetTenant])
  const tenantOption = useCallback((entry: AudienceDirectoryEntry): AudienceOption => ({ value: entry.id, label: audienceEntryLabel(entry, t) }), [t])
  const scopedOption = useCallback((entry: AudienceDirectoryEntry): AudienceOption => ({
    value: pairValue(entry.scope_id ?? targetTenant?.value ?? '', entry.id),
    label: `${targetTenant?.label ?? ''} / ${audienceEntryLabel(entry, t)}`,
  }), [t, targetTenant])

  const publishItem = confirm?.action === 'publish' ? confirm.item : null
  const audienceCountQuery = useQuery({
    queryKey: ['global-announcement-audience-count', ownerKey, publishItem?.id, publishItem?.revision],
    queryFn: async () => {
      const token = currentToken(ownerKey)
      if (!token) throw new ApiError('stale session', 401, 'permission_denied')
      const result = await globalAnnouncementsApi.audienceCount(token, publishItem!.id)
      if (!currentToken(ownerKey) || result.announcement_id !== publishItem!.id) throw new ApiError('invalid response', 502, 'invalid_response')
      return result.recipient_count
    },
    enabled: Boolean(publishItem),
    retry: false,
    gcTime: 0,
  })

  const listQuery = useQuery({
    queryKey: ['global-announcements', ownerKey, status, 20, cursor],
    enabled: Boolean(owner),
    retry: false,
    queryFn: async () => {
      const token = currentToken(ownerKey)
      if (!token) throw new ApiError('stale session', 401, 'permission_denied')
      const result = await globalAnnouncementsApi.list(token, { status: status === 'all' ? undefined : status, limit: 20, cursor })
      if (!currentToken(ownerKey) || result.items.some((item) => item.platform_scope_id !== owner![1])) {
        throw new ApiError('invalid response', 502, 'invalid_response')
      }
      return result
    },
  })

  const mutation = useMutation({
    mutationFn: async (write: WriteAttempt) => {
      const result = await write.run()
      if (!currentToken(write.ownerKey) || (Array.isArray(result) ? result : [result]).some((item) => item.platform_scope_id !== owner?.[1])) {
        throw new ApiError('invalid response', 502, 'invalid_response')
      }
      return result
    },
    onSuccess: async (_result, variables) => {
      if (!currentToken(variables.ownerKey)) return
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      setConfirm(null)
      setSelectedRowKeys([])
      setCursors([])
      await queryClient.invalidateQueries({ queryKey: ['global-announcements', ownerKey] })
      if (currentToken(variables.ownerKey)) messageApi.success(t(variables.notice))
    },
    onError: async (error, variables) => {
      if (!currentToken(variables.ownerKey)) return
      // fix-fielderr-be4: a refused draft field is said under it, not in a dialog.
      if (variables.draft && markSubmitError(error)) {
        setWriteError(null)
        setAttempt(null)
        return
      }
      setWriteError(error)
      if (variables.batch) {
        setSelectedRowKeys((keys) => keys.filter((id) => !variables.batch!.completed.includes(id)))
        setCursors([])
        await queryClient.invalidateQueries({ queryKey: ['global-announcements', variables.ownerKey] })
      }
    },
  })

  useEffect(() => {
    setAttempt(null)
    setWriteError(null)
    setSelectedRowKeys([])
    setCursors([])
    setStatus('all')
    setEditor(null)
    setConfirm(null)
  }, [ownerKey])

  if (!accessToken || !principal) return null
  if (!owner || !principal.permissions.includes('announcements.manage')) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  }

  const uncertain = isUnknownWrite(writeError)
  const writesLocked = mutation.isPending || Boolean(writeError && (uncertain || attempt?.batch))
  const begin = (key: string, run: () => Promise<WriteResult>, batch?: BatchProgress, notice = 'global.notices.saved', draft = false) => {
    if (writesLocked) return
    const next: WriteAttempt = { ownerKey, key, run, batch, notice, draft }
    setAttempt(next)
    setWriteError(null)
    mutation.mutate(next)
  }

  // Stored targets are IDs; resolve them (and their tenants) to names. Targets
  // that no longer exist show as deleted instead of exposing the raw ID.
  const resolveAudience = async (item: GlobalAnnouncement) => {
    const token = currentToken(ownerKey)
    if (!token) throw new ApiError('stale session', 401, 'permission_denied')
    const lookup = (kind: 'tenant' | 'role' | 'user', ids: string[]) => ids.length === 0 ? Promise.resolve([]) : lookupAudienceEntries(ids, async (batch) =>
      (await globalAnnouncementsApi.audienceDirectory(token, { kind, ids: batch })).items)
    const { tenant_scope_ids: tenantIDs, role_targets: roles, user_targets: users } = item.audience
    const scopeIDs = [...tenantIDs, ...roles.map((target) => target.scope_id), ...users.map((target) => target.scope_id)]
    const [tenants, roleEntries, userEntries] = await Promise.all([
      lookup('tenant', scopeIDs), lookup('role', roles.map((target) => target.role_id)), lookup('user', users.map((target) => target.user_id)),
    ])
    const deleted = t('form.deletedTarget')
    const tenantName = new Map(tenants.map((entry) => [entry.id, audienceEntryLabel(entry, t)]))
    const roleName = new Map(roleEntries.map((entry) => [`${entry.scope_id}/${entry.id}`, audienceEntryLabel(entry, t)]))
    const userName = new Map(userEntries.map((entry) => [entry.id, audienceEntryLabel(entry, t)]))
    return {
      tenant_scope_ids: tenantIDs.map((id) => ({ value: id, label: tenantName.get(id) ?? deleted })),
      role_targets: roles.map((target) => {
        const name = roleName.get(pairValue(target.scope_id, target.role_id))
        return { value: pairValue(target.scope_id, target.role_id), label: name && tenantName.has(target.scope_id) ? `${tenantName.get(target.scope_id)} / ${name}` : deleted }
      }),
      user_targets: users.map((target) => {
        const name = userName.get(target.user_id)
        return { value: pairValue(target.scope_id, target.user_id), label: name && tenantName.has(target.scope_id) ? `${tenantName.get(target.scope_id)} / ${name}` : deleted }
      }),
    }
  }

  const openEditor = async (item: GlobalAnnouncement | null) => {
    setWriteError(null)
    if (!item) {
      form.setFieldsValue({
        title: '', format: 'content', body: '', link_url: '', sort_order: 100,
        visible: true, popup: false, red: false, bold: false,
        all_tenants: true, tenant_scope_ids: [], target_tenant: [], role_targets: [], user_targets: [], withdrawal_visibility: 'retain',
      })
      setEditor({ item })
      return
    }
    setEditorLoadingID(item.id)
    try {
      const audience = await resolveAudience(item)
      if (!currentToken(ownerKey)) return
      form.setFieldsValue({
        title: item.title, format: item.format, body: item.body, link_url: item.link_url ?? '', sort_order: item.sort_order,
        visible: item.visible, popup: item.popup, red: item.red, bold: item.bold,
        all_tenants: item.audience.all_tenants, target_tenant: [], ...audience,
        withdrawal_visibility: item.withdrawal_visibility,
      })
      setEditor({ item })
    } catch (error) {
      if (currentToken(ownerKey)) setWriteError(error)
    } finally {
      setEditorLoadingID(null)
    }
  }

  const submit = async () => {
    let values: FormValues
    try {
      await form.validateFields()
      values = form.getFieldsValue(true)
    } catch {
      return
    }
    const tenantIDs = uniqueValues(values.tenant_scope_ids)
    const roles = uniqueValues(values.role_targets).map(splitPair).map(([scope_id, role_id]) => ({ scope_id, role_id }))
    const users = uniqueValues(values.user_targets).map(splitPair).map(([scope_id, user_id]) => ({ scope_id, user_id }))
    if (!values.all_tenants && tenantIDs.length + roles.length + users.length === 0) {
      form.setFields([{ name: 'tenant_scope_ids', errors: [t('form.audienceRequired')] }])
      return
    }
    const input: GlobalAnnouncementInput = {
      title: values.title.trim(), format: values.format, body: values.format === 'link' ? '' : values.body,
      link_url: values.format === 'link' ? values.link_url.trim() : '', sort_order: values.sort_order,
      visible: values.visible, popup: values.popup, red: values.red, bold: values.bold, all_tenants: values.all_tenants,
      tenant_scope_ids: values.all_tenants ? [] : tenantIDs,
      role_targets: values.all_tenants ? [] : roles,
      user_targets: values.all_tenants ? [] : users,
      withdrawal_visibility: values.withdrawal_visibility,
    }
    const key = newAnnouncementIdempotencyKey(editor?.item ? 'announcement-global-update' : 'announcement-global-create')
    if (editor?.item) begin(key, () => {
      const token = currentToken(ownerKey)
      if (!token) return Promise.reject(new ApiError('stale session', 401, 'permission_denied'))
      return globalAnnouncementsApi.update(token, editor.item!.id, { ...input, expected_revision: editor.item!.revision }, key)
    }, undefined, undefined, true)
    else begin(key, () => {
      const token = currentToken(ownerKey)
      if (!token) return Promise.reject(new ApiError('stale session', 401, 'permission_denied'))
      return globalAnnouncementsApi.create(token, input, key)
    }, undefined, undefined, true)
  }

  const transition = () => {
    if (!confirm) return
    if (confirm.action === 'archive-batch') {
      writeBatch(confirm.items, 'archive')
      return
    }
    const key = newAnnouncementIdempotencyKey(`announcement-global-${confirm.action}`)
    const { action, item } = confirm
    begin(key, () => {
      const token = currentToken(ownerKey)
      if (!token) return Promise.reject(new ApiError('stale session', 401, 'permission_denied'))
      return globalAnnouncementsApi[action](token, item.id, action === 'archive' || action === 'restore' ? item.lifecycle_revision : item.revision, key)
    }, undefined, action === 'archive' ? 'global.notices.deleted' : action === 'restore' ? 'notices.restore' : 'global.notices.saved')
  }

  const selectedItems = (listQuery.data?.items ?? []).filter((item) => selectedRowKeys.includes(item.id))
  const canToggleVisibility = selectedItems.length > 0 && selectedItems.every((item) => item.status === 'draft' && !item.archived)
  const toggleVisibility = (visible: boolean) => {
    if (!canToggleVisibility) return
    writeBatch([...selectedItems], visible ? 'show' : 'hide')
  }
  const writeBatch = (items: GlobalAnnouncement[], action: 'archive' | 'show' | 'hide') => {
    const key = newAnnouncementIdempotencyKey(`announcement-global-${action}-batch`)
    const progress: BatchProgress = { completed: [], total: items.length }
    begin(key, async () => {
      const results: GlobalAnnouncement[] = []
      for (const item of items) {
        if (progress.completed.includes(item.id)) continue
        const token = currentToken(ownerKey)
        if (!token) throw new ApiError('stale session', 401, 'permission_denied')
        const itemKey = batchItemIdempotencyKey(key, item.id)
        const result = action === 'archive'
          ? await globalAnnouncementsApi.archive(token, item.id, item.lifecycle_revision, itemKey)
          : await globalAnnouncementsApi.update(token, item.id, {
            ...globalAnnouncementInput(item, action === 'show'), expected_revision: item.revision,
          }, itemKey)
        if (!currentToken(ownerKey) || result.platform_scope_id !== owner[1] || result.id !== item.id) {
          throw new ApiError('invalid response', 502, 'invalid_response')
        }
        results.push(result)
        progress.completed.push(item.id)
      }
      return results
    }, progress, action === 'archive' ? 'global.notices.deleted' : 'global.notices.saved')
  }

  const closeAndRefresh = () => {
    setAttempt(null)
    setWriteError(null)
    setConfirm(null)
    setEditor(null)
    setSelectedRowKeys([])
    setCursors([])
    void queryClient.invalidateQueries({ queryKey: ['global-announcements', ownerKey] })
  }
  const batchProgress = writeError && attempt?.batch ? t('global.notices.batchProgress', {
    completed: formatNumber(attempt.batch.completed.length, i18n.resolvedLanguage ?? 'zh-CN'),
    total: formatNumber(attempt.batch.total, i18n.resolvedLanguage ?? 'zh-CN'),
  }) : undefined
  const recoveryActions = <Space>{attempt && (attempt.batch || uncertain) ? <Button size="small" loading={mutation.isPending} onClick={() => mutation.mutate(attempt)}>{t('actions.retrySameRequest')}</Button> : null}<Button size="small" disabled={mutation.isPending} onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button></Space>

  const columns: TableColumnsType<GlobalAnnouncement> = [
    { title: t('columns.id'), dataIndex: 'id', width: 130, ellipsis: true },
    { title: t('columns.title'), dataIndex: 'title', width: 260, ellipsis: true, render: (value: string, item) => <Space size={6}><span style={{ color: item.red ? 'var(--cdnca-color-error)' : undefined, fontWeight: item.bold ? 700 : undefined }}>{value}</span><Tag color={item.archived ? 'default' : item.status === 'published' ? 'green' : item.status === 'draft' ? 'gold' : 'default'}>{t(`states.${item.archived ? 'archived' : item.status}`)}</Tag></Space> },
    { title: t('columns.jump'), key: 'jump', width: 80, render: (_value, item) => item.format === 'link' ? t('values.link') : t('values.content') },
    { title: t('columns.popup'), key: 'popup', width: 80, render: (_value, item) => item.popup ? t('values.popup') : t('values.normal') },
    { title: t('columns.style'), key: 'style', width: 100, render: (_value, item) => [item.red ? t('values.red') : '', item.bold ? t('values.bold') : ''].filter(Boolean).join(' ') || '—' },
    { title: t('columns.visible'), key: 'visible', width: 90, render: (_value, item) => item.visible ? t('values.visible') : t('values.hidden') },
    { title: t('columns.sort'), dataIndex: 'sort_order', width: 70, render: (value: number) => formatNumber(value, i18n.resolvedLanguage ?? 'zh-CN') },
    { title: t('columns.createdAt'), dataIndex: 'created_at', width: 175, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') },
    { title: t('columns.updatedAt'), dataIndex: 'state_changed_at', width: 175, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') },
    {
      title: t('columns.action'), key: 'actions', width: 300,
      render: (_value, item) => <Space wrap>
        {!item.archived && item.status === 'draft' ? <Button type="link" size="small" disabled={writesLocked} loading={editorLoadingID === item.id} icon={<Edit3 size={14} />} onClick={() => void openEditor(item)}>{t('actions.edit')}</Button> : null}
        {!item.archived && item.status === 'draft' ? <Button type="link" size="small" disabled={writesLocked} icon={<Send size={14} />} onClick={() => setConfirm({ action: 'publish', item })}>{t('actions.publish')}</Button> : null}
        {item.status === 'published' ? <Button danger type="link" size="small" disabled={writesLocked} icon={<Undo2 size={14} />} onClick={() => setConfirm({ action: 'withdraw', item })}>{t('actions.withdraw')}</Button> : null}
        <Button type="link" size="small" danger={!item.archived} disabled={writesLocked} onClick={() => setConfirm({ action: item.archived ? 'restore' : 'archive', item })}>{item.archived ? t('actions.restore') : t('global.actions.delete')}</Button>
      </Space>,
    },
  ]

  return <section className="identity-page announcement-page" aria-labelledby="global-announcement-title">
    {messageContext}
    <h1 id="global-announcement-title" className="visually-hidden">{t('title')}</h1>
    <div className="identity-toolbar announcement-toolbar">
      <Select aria-label={t('filters.status')} value={status} onChange={(value: GlobalStatus | 'all') => { setStatus(value); setCursors([]); setSelectedRowKeys([]) }} options={[
        { value: 'all', label: t('filters.all') }, ...(['draft', 'published', 'withdrawn', 'archived'] as GlobalStatus[]).map((value) => ({ value, label: t(`states.${value}`) })),
      ]} />
      <Button icon={<Eye size={15} />} disabled={!canToggleVisibility || mutation.isPending || writesLocked} onClick={() => toggleVisibility(true)}>{t('global.actions.show')}</Button>
      <Button icon={<EyeOff size={15} />} disabled={!canToggleVisibility || mutation.isPending || writesLocked} onClick={() => toggleVisibility(false)}>{t('global.actions.hide')}</Button>
      <Button danger icon={<Trash2 size={15} />} disabled={selectedItems.length === 0 || writesLocked} onClick={() => setConfirm({ action: 'archive-batch', items: [...selectedItems] })}>{t('global.actions.deleteSelected')}</Button>
      <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => void openEditor(null)}>{t('form.createTitle')}</Button>
      <Button icon={<RefreshCw size={15} />} loading={listQuery.isFetching} onClick={() => void listQuery.refetch()}>{t('actions.refresh')}</Button>
    </div>
    {listQuery.isError ? <FeedbackWhen title={errorText(listQuery.error, t)} action={<Button size="small" onClick={() => void listQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
    {writeError ? (uncertain ? <OutcomeUnknown title={t('uncertainty.title')} detail={confirm ? undefined : batchProgress} action={confirm ? undefined : recoveryActions} />
      : attempt?.batch && !confirm ? <OutcomeUnknown type="error" title={errorText(writeError, t)} detail={batchProgress} action={recoveryActions} />
      : <FeedbackWhen title={errorText(writeError, t)} detail={confirm ? undefined : batchProgress} action={confirm ? undefined : recoveryActions} />) : null}
    <div className="identity-table-scroll announcement-table-scroll" data-testid="global-announcement-table" aria-busy={listQuery.isPending || listQuery.isFetching}>
      <Table rowKey="id" size="small" columns={columns} dataSource={listQuery.data?.items ?? []} loading={listQuery.isPending} pagination={false} scroll={{ x: 1460 }} locale={{ emptyText: listQuery.isError ? <DataState status="error" message={errorText(listQuery.error, t)} onRetry={() => void listQuery.refetch()} /> : t('values.empty') }} rowSelection={{
        selectedRowKeys,
        onChange: (keys) => setSelectedRowKeys(keys.map(String)),
        getCheckboxProps: (item) => ({ disabled: item.archived || writesLocked }),
      }} />
    </div>
    <div className="identity-pagination">
      <Button disabled={cursors.length === 0} onClick={() => { setSelectedRowKeys([]); setCursors((value) => value.slice(0, -1)) }}>{t('actions.previousPage')}</Button>
      <Button disabled={!listQuery.data?.next_cursor} onClick={() => { if (listQuery.data?.next_cursor) { setSelectedRowKeys([]); setCursors((value) => [...value, listQuery.data!.next_cursor!]) } }}>{t('actions.nextPage')}</Button>
    </div>

    <Modal className="announcement-editor-modal" title={editor?.item ? t('form.editTitle') : t('form.createTitle')} open={editor !== null} width={720} onCancel={() => setEditor(null)} closable={!mutation.isPending} maskClosable={!mutation.isPending} footer={[<Button key="cancel" onClick={() => setEditor(null)} disabled={mutation.isPending}>{t('actions.cancel')}</Button>, <Button key="submit" type="primary" loading={mutation.isPending} onClick={() => void submit()}>{t('editorConfirm')}</Button>]} destroyOnHidden>
      <Form form={form} layout="horizontal" className="announcement-compat-form" disabled={mutation.isPending} initialValues={{ format: 'content', sort_order: 100, visible: true, popup: false, red: false, bold: false, all_tenants: true, withdrawal_visibility: 'retain' }}>
        <div className="announcement-form-section"><h2><span />{t('form.basic')}</h2>
          <Form.Item name="title" label={t('form.title')} rules={[{ required: true, whitespace: true, message: t('form.titleRequired') }]}><Input placeholder={t('form.titlePlaceholder')} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.format !== next.format}>{({ getFieldValue }) => <Form.Item label={t('form.format')}><div className="announcement-format-switch"><Button type={getFieldValue('format') === 'content' ? 'primary' : 'default'} className="announcement-format-button" onClick={() => form.setFieldValue('format', 'content')} aria-pressed={getFieldValue('format') === 'content'}>{t('form.showContent')}</Button><Button type={getFieldValue('format') === 'link' ? 'primary' : 'default'} className="announcement-format-button" onClick={() => form.setFieldValue('format', 'link')} aria-pressed={getFieldValue('format') === 'link'}>{t('form.jumpLink')}</Button></div></Form.Item>}</Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.format !== next.format}>{({ getFieldValue }) => getFieldValue('format') === 'link'
            ? <Form.Item name="link_url" label={t('form.link')} rules={[{ required: true, whitespace: true, message: t('form.linkRequired') }]}><Input placeholder={t('form.linkPlaceholder')} /></Form.Item>
            : <Form.Item name="body" label={t('form.body')} rules={[{ required: true, whitespace: true, message: t('form.bodyRequired') }]}><Input.TextArea rows={10} maxLength={65536} placeholder={t('form.bodyPlaceholder')} /></Form.Item>}</Form.Item>
          <Form.Item name="sort_order" label={t('form.sort')} rules={[{ required: true, type: 'number', min: 0, max: 999999, message: t('form.sortRequired') }]}><InputNumber className="announcement-sort-input" controls={false} /></Form.Item>
        </div>
        <div className="announcement-form-section"><h2><span />{t('form.displayState')}</h2>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.visible !== next.visible}>{({ getFieldValue }) => <Form.Item label={t('form.visible')}><Space><Form.Item name="visible" valuePropName="checked" noStyle><Switch aria-label={t('form.visible')} /></Form.Item><span>{getFieldValue('visible') ? t('form.alreadyVisible') : t('form.hidden')}</span></Space></Form.Item>}</Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.popup !== next.popup}>{({ getFieldValue }) => <Form.Item label={t('form.popup')}><Space><Form.Item name="popup" valuePropName="checked" noStyle><Switch aria-label={t('form.popup')} /></Form.Item><span>{getFieldValue('popup') ? t('form.popupDisplay') : t('form.normalDisplay')}</span></Space></Form.Item>}</Form.Item>
          <Form.Item label={t('form.style')}><Space><Form.Item name="red" valuePropName="checked" noStyle><Checkbox>{t('form.red')}</Checkbox></Form.Item><Form.Item name="bold" valuePropName="checked" noStyle><Checkbox>{t('form.bold')}</Checkbox></Form.Item></Space></Form.Item>
        </div>
        {/* Audience is a reachable "advanced" section (C32), summarized while folded. */}
        <details className="announcement-advanced-audience">
          <summary><Form.Item noStyle shouldUpdate={(previous, next) => previous.all_tenants !== next.all_tenants}>{({ getFieldValue }) =>
            <span>{t('form.advancedAudience')}：{getFieldValue('all_tenants') ? t('global.form.allTenants') : t('global.form.selectedTargets')}</span>}</Form.Item></summary>
          <Form.Item name="all_tenants" label={t('form.audience')}><Select options={[{ value: true, label: t('global.form.allTenants') }, { value: false, label: t('global.form.selectedTargets') }]} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, next) => previous.all_tenants !== next.all_tenants}>{({ getFieldValue }) => getFieldValue('all_tenants') ? null : <>
            <Form.Item name="tenant_scope_ids" label={t('global.form.tenants')} extra={t('global.form.tenantsHint')}><AnnouncementAudienceSelect ariaLabel={t('global.form.tenants')} search={searchTenants} toOption={tenantOption} placeholder={t('global.form.searchTenants')} /></Form.Item>
            <Form.Item name="target_tenant" label={t('global.form.targetTenant')} extra={t('global.form.targetTenantHint')}><AnnouncementAudienceSelect maxCount={1} ariaLabel={t('global.form.targetTenant')} search={searchTenants} toOption={tenantOption} placeholder={t('global.form.searchTenants')} /></Form.Item>
            <Form.Item name="role_targets" label={t('global.form.roles')}><AnnouncementAudienceSelect ariaLabel={t('global.form.roles')} search={searchRoles} toOption={scopedOption} placeholder={targetTenant ? t('form.searchRoles') : t('global.form.pickTenantFirst')} /></Form.Item>
            <Form.Item name="user_targets" label={t('global.form.users')}><AnnouncementAudienceSelect ariaLabel={t('global.form.users')} search={searchUsers} toOption={scopedOption} placeholder={targetTenant ? t('form.searchUsers') : t('global.form.pickTenantFirst')} /></Form.Item>
          </>}</Form.Item>
          <Form.Item name="withdrawal_visibility" label={t('form.withdrawalVisibility')}><Select options={[{ value: 'retain', label: t('form.retain') }, { value: 'hide', label: t('form.hide') }]} /></Form.Item>
        </details>
      </Form>
    </Modal>

    <Modal open={confirm !== null} title={confirm?.action === 'publish' ? t('confirm.publishTitle') : confirm?.action === 'archive' || confirm?.action === 'archive-batch' ? t('global.confirm.deleteTitle') : confirm?.action === 'restore' ? t('confirm.restoreTitle') : t('confirm.withdrawTitle')} onCancel={() => setConfirm(null)} onOk={transition} confirmLoading={mutation.isPending} okButtonProps={{ disabled: writesLocked || (Boolean(publishItem) && (audienceCountQuery.data ?? 0) === 0) }} cancelButtonProps={{ disabled: writesLocked }} closable={!writesLocked} maskClosable={!writesLocked} okText={t('actions.confirm')} cancelText={t('actions.cancel')} footer={writeError ? recoveryActions : undefined}>
      <p>{confirm?.action === 'publish' ? t('global.confirm.publishDescription') : confirm?.action === 'archive' || confirm?.action === 'archive-batch' ? t('global.confirm.deleteDescription') : confirm?.action === 'restore' ? t('confirm.restoreDescription') : t('confirm.withdrawDescription')}</p>
      {batchProgress ? <p>{batchProgress}</p> : null}
      {publishItem ? <AudienceCountNotice loading={audienceCountQuery.isPending} error={audienceCountQuery.isError ? errorText(audienceCountQuery.error, t) : null} count={audienceCountQuery.data} onRetry={() => void audienceCountQuery.refetch()} /> : null}
    </Modal>
  </section>
}
