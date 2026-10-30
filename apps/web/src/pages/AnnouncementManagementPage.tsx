import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Form, Input, InputNumber, Modal, Result, Select, Space, Spin, Switch, Table, Tag, type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback, FeedbackWhen, useFormSubmitError } from '@cdnca/ui'
import { CalendarClock, Check, Edit3, Eye, FilePenLine, Plus, RotateCcw, Send, Trash2, Undo2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import {
  announcementsApi,
  newAnnouncementIdempotencyKey,
  type Announcement,
  type AnnouncementInput,
  type AnnouncementStatus,
  type AudienceDirectoryEntry,
} from '../api/announcements'
import { ApiError, type Principal } from '../api/auth'
import { useSessionStore } from '../auth/session'
import { formatDateTime, formatNumber } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import AnnouncementAudienceSelect, { AudienceCountNotice } from './AnnouncementAudienceSelect'
import { audienceEntryLabel, lookupAudienceEntries, type AudienceOption } from './announcementAudience'
import GlobalAnnouncementManagement from './GlobalAnnouncementManagement'
import './AnnouncementManagementPage.css'

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
  all: boolean
  user_ids: AudienceOption[]
  group_ids: AudienceOption[]
  withdrawal_visibility: 'retain' | 'hide'
}

type Editor = { mode: 'create'; item: null } | { mode: 'edit' | 'revise'; item: Announcement }
type WriteIntent =
  | { action: 'create'; input: AnnouncementInput }
  | { action: 'update' | 'revise'; item: Announcement; input: AnnouncementInput }
  | { action: 'schedule'; item: Announcement; publish_at: string }
  | { action: 'publish' | 'withdraw' | 'archive' | 'restore'; item: Announcement }
  | { action: 'archive-batch'; items: Announcement[]; completed: string[] }
type ConfirmationIntent =
  | { action: 'publish' | 'withdraw' | 'archive' | 'restore'; item: Announcement }
  | { action: 'archive-batch'; items: Announcement[] }
type WriteAttempt = { intent: WriteIntent; key: string }
type AnnouncementOwner = readonly [Principal['scope_kind'], string, string, string, number]

const staleAnnouncementRead = new Error('stale announcement read')

function announcementOwner(principal: Principal, sessionEpoch: number): AnnouncementOwner | null {
  if (
    principal.scope_kind !== 'tenant' || !principal.scope_id || !principal.tenant_id ||
    !principal.user_id || !sessionEpoch
  ) return null
  return [principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, sessionEpoch]
}

function currentAnnouncementSessionAccess(ownerKey: string): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || !principal.permissions.includes('announcements.manage')) return null
  const owner = announcementOwner(principal, sessionEpoch)
  return owner && JSON.stringify(owner) === ownerKey ? accessToken : null
}

function invalidAnnouncementResponse(): ApiError {
  return new ApiError('API response was invalid', 502, 'invalid_response')
}

function assertAnnouncementOwner(owner: AnnouncementOwner, value: Announcement, expectedID?: string): Announcement {
  if (value.scope_id !== owner[1] || (expectedID && value.id !== expectedID)) throw invalidAnnouncementResponse()
  return value
}

function optionValues(value: AudienceOption[] | undefined): string[] {
  return [...new Set((value ?? []).map((item) => item.value))]
}

function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status === 429 || error.status >= 500
}

function errorText(error: unknown, t: (key: string) => string) {
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'permission_denied': return t('errors.permissionDenied')
      case 'version_conflict': return t('errors.versionConflict')
      case 'idempotency_conflict': return t('errors.idempotencyConflict')
      case 'empty_audience': return t('errors.emptyAudience')
      case 'audience_scope_denied': return t('errors.audienceScopeDenied')
      case 'announcement_not_found': return t('errors.notFound')
      case 'announcement_state_conflict': return t('errors.stateConflict')
      case 'validation_error': return t('errors.validation')
    }
  }
  return localizedUnknownApiError(error, t('errors.requestFailed'))
}

function intentNotice(action: WriteIntent['action'], t: (key: string) => string): string {
  return t(`notices.${action}`)
}

export default function AnnouncementManagementPage() {
  const { t } = useTranslation('announcements')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const owner = principal ? announcementOwner(principal, sessionEpoch) : null

  if (!accessToken || !principal) return null
  if (principal.scope_kind === 'platform' && principal.tenant_id === null && principal.permissions.includes('announcements.manage')) {
    return <GlobalAnnouncementManagement />
  }
  if (!owner || !principal.permissions.includes('announcements.manage')) {
    return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  }

  const ownerKey = JSON.stringify(owner)
  return (
    <AnnouncementManagementContent
      key={ownerKey}
      owner={owner}
      ownerKey={ownerKey}
    />
  )
}

function AnnouncementManagementContent({
  owner,
  ownerKey,
}: {
  owner: AnnouncementOwner
  ownerKey: string
}) {
  const { t, i18n } = useTranslation('announcements')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [status, setStatus] = useState<AnnouncementStatus | 'all'>('all')
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [detailID, setDetailID] = useState<string | null>(null)
  const [scheduleItem, setScheduleItem] = useState<Announcement | null>(null)
  const [publishAt, setPublishAt] = useState('')
  const [scheduleValidation, setScheduleValidation] = useState<string | null>(null)
  const [confirm, setConfirm] = useState<ConfirmationIntent | null>(null)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [attempt, setAttempt] = useState<WriteAttempt | null>(null)
  const [writeError, setWriteError] = useState<unknown>(null)
  const [editorLoadingID, setEditorLoadingID] = useState<string | null>(null)
  const [form] = Form.useForm<FormValues>()
  const markSubmitError = useFormSubmitError(form)
  const queryOwner = useRef(owner).current
  const lineageActiveRef = useRef(true)
  const queryPrefix = useMemo(() => ['announcements', ...queryOwner] as const, [queryOwner])
  const detailPrefix = useMemo(() => ['announcement-detail', ...queryOwner] as const, [queryOwner])
  const mutationPrefix = useMemo(() => ['announcement-mutation', ...queryOwner] as const, [queryOwner])
  const currentSessionMatches = useCallback(() => (
    lineageActiveRef.current && Boolean(currentAnnouncementSessionAccess(ownerKey))
  ), [ownerKey])
  const cursor = cursorStack.at(-1)

  useEffect(() => {
    lineageActiveRef.current = true
    const cleanupOwnerCache = () => {
      queryClient.removeQueries({ queryKey: queryPrefix })
      queryClient.removeQueries({ queryKey: detailPrefix })
      for (const mutation of queryClient.getMutationCache().findAll({ mutationKey: mutationPrefix })) {
        queryClient.getMutationCache().remove(mutation)
      }
    }
    return () => {
      lineageActiveRef.current = false
      if (!currentAnnouncementSessionAccess(ownerKey)) cleanupOwnerCache()
    }
  }, [currentSessionMatches, detailPrefix, mutationPrefix, ownerKey, queryClient, queryPrefix])

  const listQuery = useQuery({
    queryKey: [...queryPrefix, status, 20, cursor],
    queryFn: async () => {
      const token = currentAnnouncementSessionAccess(ownerKey)
      if (!token) throw staleAnnouncementRead
      try {
        const result = await announcementsApi.list(token, { status: status === 'all' ? undefined : status, limit: 20, cursor })
        if (!currentSessionMatches()) throw staleAnnouncementRead
        for (const item of result.items) assertAnnouncementOwner(queryOwner, item)
        return result
      } catch (error) {
        if (!currentSessionMatches()) throw staleAnnouncementRead
        throw error
      }
    },
    retry: false,
  })
  const detailQuery = useQuery({
    queryKey: [...detailPrefix, detailID],
    queryFn: async () => {
      const token = currentAnnouncementSessionAccess(ownerKey)
      if (!token) throw staleAnnouncementRead
      try {
        const result = await announcementsApi.get(token, detailID!)
        if (!currentSessionMatches()) throw staleAnnouncementRead
        return assertAnnouncementOwner(queryOwner, result, detailID!)
      } catch (error) {
        if (!currentSessionMatches()) throw staleAnnouncementRead
        throw error
      }
    },
    enabled: Boolean(detailID),
    retry: false,
  })

  const openDetail = useCallback((item: Announcement) => setDetailID(item.id), [])

  const searchDirectory = useCallback((kind: 'user' | 'role') => async (search: string): Promise<AudienceDirectoryEntry[]> => {
    const token = currentAnnouncementSessionAccess(ownerKey)
    if (!token) throw staleAnnouncementRead
    const result = await announcementsApi.audienceDirectory(token, { kind, search })
    if (!currentSessionMatches()) throw staleAnnouncementRead
    return result.items
  }, [currentSessionMatches, ownerKey])
  const searchUsers = useMemo(() => searchDirectory('user'), [searchDirectory])
  const searchRoles = useMemo(() => searchDirectory('role'), [searchDirectory])
  const toAudienceOption = useCallback((entry: AudienceDirectoryEntry): AudienceOption => ({ value: entry.id, label: audienceEntryLabel(entry, t) }), [t])

  // Publication delivers to the recipients resolved at that moment; preview the
  // same resolution so the confirmation states who will receive it.
  const publishItem = confirm?.action === 'publish' ? confirm.item : null
  const audienceCountQuery = useQuery({
    queryKey: [...detailPrefix, 'audience-count', publishItem?.id, publishItem?.version, publishItem?.revision],
    queryFn: async () => {
      const token = currentAnnouncementSessionAccess(ownerKey)
      if (!token) throw staleAnnouncementRead
      const result = await announcementsApi.audienceCount(token, publishItem!.id)
      if (!currentSessionMatches() || result.announcement_id !== publishItem!.id) throw staleAnnouncementRead
      return result.recipient_count
    },
    enabled: Boolean(publishItem),
    retry: false,
    gcTime: 0,
  })

  const openEditor = useCallback(async (item: Announcement | null, mode: 'create' | 'edit' | 'revise') => {
    setWriteError(null)
    if (!item || mode === 'create') {
      form.resetFields()
      form.setFieldsValue({ format: 'content', body: '', link_url: '', sort_order: 100, visible: true, popup: false, red: false, bold: false, all: true, user_ids: [], group_ids: [], withdrawal_visibility: 'retain' })
      setEditor({ mode: 'create', item: null })
      return
    }
    setEditorLoadingID(`${mode}:${item.id}`)
    try {
      const latest = await queryClient.fetchQuery({
        queryKey: [...detailPrefix, item.id],
        queryFn: async () => {
          const token = currentAnnouncementSessionAccess(ownerKey)
          if (!token) throw staleAnnouncementRead
          const result = await announcementsApi.get(token, item.id)
          if (!currentSessionMatches()) throw staleAnnouncementRead
          return assertAnnouncementOwner(queryOwner, result, item.id)
        },
      })
      if (!currentSessionMatches()) return
      // Stored audiences are IDs only; resolve them to names. Targets that no
      // longer exist show as deleted instead of exposing the raw ID.
      const token = currentAnnouncementSessionAccess(ownerKey)
      if (!token) return
      const resolve = async (kind: 'user' | 'role', stored: string[] | undefined): Promise<AudienceOption[]> => {
        if (!stored?.length) return []
        const found = new Map((await lookupAudienceEntries(stored, async (batch) =>
          (await announcementsApi.audienceDirectory(token, { kind, ids: batch })).items)).map((entry) => [entry.id, entry]))
        return stored.map((id) => {
          const entry = found.get(id)
          return { value: id, label: entry ? audienceEntryLabel(entry, t) : t('form.deletedTarget') }
        })
      }
      const [userOptions, groupOptions] = await Promise.all([resolve('user', latest.audience.user_ids), resolve('role', latest.audience.group_ids)])
      if (!currentSessionMatches()) return
      form.setFieldsValue({
        title: latest.title,
        format: latest.format,
        body: latest.body,
        link_url: latest.link_url ?? '',
        sort_order: latest.sort_order,
        visible: latest.visible,
        popup: latest.popup,
        red: latest.red,
        bold: latest.bold,
        all: latest.audience.all,
        user_ids: userOptions,
        group_ids: groupOptions,
        withdrawal_visibility: latest.withdrawal_visibility,
      })
      setEditor({ mode, item: latest })
    } catch (error) {
      if (currentSessionMatches()) feedback.error(errorText(error, t))
    } finally {
      if (currentSessionMatches()) setEditorLoadingID(null)
    }
  }, [currentSessionMatches, detailPrefix, form, feedback, ownerKey, queryClient, queryOwner, t])

  const mutation = useMutation({
    mutationKey: mutationPrefix,
    mutationFn: async ({ intent, key }: WriteAttempt) => {
      const token = currentAnnouncementSessionAccess(ownerKey)
      if (!token) throw staleAnnouncementRead
      let result: Announcement | undefined
      if (intent.action === 'create') result = await announcementsApi.create(token, intent.input, key)
      else if (intent.action === 'update') {
        result = await announcementsApi.update(token, intent.item.id, { ...intent.input, version: intent.item.version, expected_revision: intent.item.revision }, key)
      } else if (intent.action === 'revise') {
        result = await announcementsApi.revise(token, intent.item.id, { ...intent.input, expected_head_version: intent.item.head_version }, key)
      } else if (intent.action === 'schedule') {
        result = await announcementsApi.schedule(token, intent.item.id, { version: intent.item.version, expected_revision: intent.item.revision, publish_at: intent.publish_at }, key)
      } else if (intent.action === 'publish') {
        result = await announcementsApi.publish(token, intent.item.id, { version: intent.item.version, expected_revision: intent.item.revision }, key)
      } else if (intent.action === 'withdraw') {
        result = await announcementsApi.withdraw(token, intent.item.id, { version: intent.item.version, expected_revision: intent.item.revision }, key)
      } else if (intent.action === 'archive') {
        result = await announcementsApi.archive(token, intent.item.id, intent.item.lifecycle_revision, key)
      } else if (intent.action === 'restore') {
        result = await announcementsApi.restore(token, intent.item.id, intent.item.lifecycle_revision, key)
      } else if (intent.action === 'archive-batch') {
        for (const item of intent.items) {
          if (intent.completed.includes(item.id)) continue
          const currentToken = currentAnnouncementSessionAccess(ownerKey)
          if (!currentToken) throw staleAnnouncementRead
          result = await announcementsApi.archive(currentToken, item.id, item.lifecycle_revision, `${key}-${item.id}`)
          if (!currentSessionMatches()) throw staleAnnouncementRead
          assertAnnouncementOwner(queryOwner, result, item.id)
          intent.completed.push(item.id)
        }
        if (!result) result = intent.items.at(-1)!
      }
      if (!result) throw staleAnnouncementRead
      if (!currentSessionMatches()) throw staleAnnouncementRead
      return intent.action === 'archive-batch'
        ? result
        : assertAnnouncementOwner(queryOwner, result, intent.action === 'create' ? undefined : intent.item.id)
    },
    onSuccess: async (result, variables) => {
      if (!currentSessionMatches()) return
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      setConfirm(null)
      setSelectedRowKeys([])
      setScheduleItem(null)
      await queryClient.invalidateQueries({ queryKey: queryPrefix })
      if (variables.intent.action !== 'create' && variables.intent.action !== 'archive-batch') {
        queryClient.setQueryData([...detailPrefix, variables.intent.item.id], result)
      }
      messageApi.success(intentNotice(variables.intent.action, t))
    },
    onError: async (error, variables) => {
      if (!currentSessionMatches()) return
      // fix-fielderr-be4: a refused draft field is said under it; the editor stays open.
      const action = variables.intent.action
      if ((action === 'create' || action === 'update' || action === 'revise') && markSubmitError(error)) {
        setWriteError(null)
        setAttempt(null)
        return
      }
      setWriteError(error)
      if (variables.intent.action === 'archive-batch') {
        const completed = variables.intent.completed
        setSelectedRowKeys((keys) => keys.filter((id) => !completed.includes(id)))
        await queryClient.invalidateQueries({ queryKey: queryPrefix })
        if (!currentSessionMatches()) return
      }
      if (outcomeUnknown(error)) {
        setAttempt(variables)
        return
      }
      setAttempt(null)
      setEditor(null)
      setConfirm(null)
      setScheduleItem(null)
      if (error instanceof ApiError && error.code === 'version_conflict' && variables.intent.action !== 'archive-batch') {
        await queryClient.invalidateQueries({ queryKey: queryPrefix })
        if (variables.intent.action !== 'create') {
          const id = variables.intent.item.id
          await queryClient.invalidateQueries({ queryKey: [...detailPrefix, id] })
          try {
            await queryClient.fetchQuery({
              queryKey: [...detailPrefix, id],
              queryFn: async () => {
                const token = currentAnnouncementSessionAccess(ownerKey)
                if (!token) throw staleAnnouncementRead
                const result = await announcementsApi.get(token, id)
                if (!currentSessionMatches()) throw staleAnnouncementRead
                return assertAnnouncementOwner(queryOwner, result, id)
              },
            })
          } catch {
            // The localized conflict remains visible while a later open retries detail loading.
          }
        }
      }
    },
  })

  const beginWrite = (intent: WriteIntent) => {
    if (attempt || mutation.isPending) return
    const operation = intent.action === 'update' || intent.action === 'revise' ? `${intent.action}-${intent.item.id}` : intent.action
    const nextAttempt = { intent, key: newAnnouncementIdempotencyKey(`announcement-${operation}`) }
    setAttempt(nextAttempt)
    setWriteError(null)
    mutation.mutate(nextAttempt)
  }

  const retryWrite = () => { if (attempt) mutation.mutate(attempt) }
  const closeAndRefresh = () => {
    setAttempt(null)
    setWriteError(null)
    setEditor(null)
    setConfirm(null)
    setScheduleItem(null)
    void listQuery.refetch()
  }
  const uncertain = Boolean(attempt && writeError && outcomeUnknown(writeError))
  const writesLocked = mutation.isPending || uncertain
  const uncertainActions = uncertain ? <Space>
    <Button type="primary" loading={mutation.isPending} onClick={retryWrite}>{t('actions.retrySameRequest')}</Button>
    <Button disabled={mutation.isPending} onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button>
  </Space> : null

  const submit = async () => {
    try {
      const values = await form.validateFields()
      const userIDs = values.all ? [] : optionValues(values.user_ids)
      const groupIDs = values.all ? [] : optionValues(values.group_ids)
      if (!values.all && userIDs.length === 0 && groupIDs.length === 0) {
        form.setFields([{ name: 'user_ids', errors: [t('form.audienceRequired')] }])
        return
      }
      const input: AnnouncementInput = {
        title: values.title.trim(), format: values.format, body: values.format === 'content' ? values.body : '',
        link_url: values.format === 'link' ? values.link_url.trim() : '', sort_order: values.sort_order,
        visible: values.visible, popup: values.popup, red: values.red, bold: values.bold, all: values.all,
        user_ids: userIDs, group_ids: groupIDs, withdrawal_visibility: values.withdrawal_visibility,
      }
      if (!editor || editor.mode === 'create') beginWrite({ action: 'create', input })
      else if (editor.mode === 'edit') beginWrite({ action: 'update', item: editor.item, input })
      else beginWrite({ action: 'revise', item: editor.item, input })
    } catch {
      // Form validation renders the localized field errors.
    }
  }

  const columns = useMemo<TableColumnsType<Announcement>>(() => [
    { title: t('columns.id'), dataIndex: 'id', width: 220, ellipsis: true },
    { title: t('columns.title'), dataIndex: 'title', width: 220, ellipsis: true, render: (value: string, item) => <Space size={6}><span>{value}</span><Tag color={item.archived ? 'default' : item.status === 'published' ? 'green' : item.status === 'scheduled' ? 'blue' : item.status === 'withdrawn' ? 'default' : 'gold'}>{item.archived ? t('states.archived') : t(`states.${item.status}`)}</Tag></Space> },
    { title: t('columns.jump'), key: 'jump', width: 90, render: (_value, item) => item.format === 'link' ? t('values.link') : t('values.content') },
    { title: t('columns.popup'), key: 'popup', width: 90, render: (_value, item) => item.popup ? t('values.popup') : t('values.normal') },
    { title: t('columns.style'), key: 'style', width: 110, render: (_value, item) => [item.red ? t('values.red') : '', item.bold ? t('values.bold') : ''].filter(Boolean).join(' ') || '—' },
    { title: t('columns.visible'), key: 'visible', width: 90, render: (_value, item) => item.visible ? t('values.visible') : t('values.hidden') },
    { title: t('columns.sort'), dataIndex: 'sort_order', width: 80 },
    { title: t('columns.createdAt'), dataIndex: 'created_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value },
    { title: t('columns.updatedAt'), dataIndex: 'state_changed_at', width: 180, render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? 'zh-CN') || value },
    { title: t('columns.changedAt'), dataIndex: 'state_changed_at', className: 'announcement-legacy-column', width: 1 },
    {
      title: t('columns.action'), key: 'action', width: 430,
      render: (_value, item) => <Space wrap>
        <Button type="link" size="small" icon={<Eye size={14} />} disabled={writesLocked} onClick={() => openDetail(item)}>{t('actions.view')}</Button>
        {item.status === 'draft' ? <Button type="link" size="small" icon={<Edit3 size={14} />} loading={editorLoadingID === `edit:${item.id}`} disabled={writesLocked} onClick={() => void openEditor(item, 'edit')}>{t('actions.edit')}</Button> : null}
        {item.status === 'draft' ? <Button type="link" size="small" icon={<CalendarClock size={14} />} disabled={writesLocked} onClick={() => { setScheduleValidation(null); setPublishAt(''); setScheduleItem(item) }}>{t('actions.schedule')}</Button> : null}
        {(item.status === 'draft' || item.status === 'scheduled') ? <Button type="link" size="small" icon={<Send size={14} />} disabled={writesLocked} onClick={() => setConfirm({ action: 'publish', item })}>{t('actions.publish')}</Button> : null}
        {(item.status === 'published' || item.status === 'withdrawn') ? <Button type="link" size="small" icon={<FilePenLine size={14} />} loading={editorLoadingID === `revise:${item.id}`} disabled={writesLocked} onClick={() => void openEditor(item, 'revise')}>{t('actions.revise')}</Button> : null}
        {(item.status === 'published' || item.status === 'scheduled') ? <Button type="link" size="small" danger icon={<Undo2 size={14} />} disabled={writesLocked} onClick={() => setConfirm({ action: 'withdraw', item })}>{t('actions.withdraw')}</Button> : null}
        {item.archived ? <Button type="link" size="small" icon={<RotateCcw size={14} />} disabled={writesLocked} onClick={() => setConfirm({ action: 'restore', item })}>{t('actions.restore')}</Button> : <Button type="link" size="small" danger icon={<Trash2 size={14} />} disabled={writesLocked} onClick={() => setConfirm({ action: 'archive', item })}>{t('actions.delete')}</Button>}
      </Space>,
    },
  ], [editorLoadingID, i18n.resolvedLanguage, openDetail, openEditor, t, writesLocked])

  if (listQuery.isError && (listQuery.error as ApiError)?.code === 'permission_denied') return <Result className="identity-page identity-forbidden" status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.permissionDenied')} />
  const items = listQuery.data?.items ?? []
  const listError = listQuery.error && listQuery.error instanceof ApiError ? errorText(listQuery.error, t) : t('errors.requestFailed')
  const detail = detailQuery.data
  const failedBatch = writeError && mutation.variables?.intent.action === 'archive-batch' ? mutation.variables.intent : null
  const batchProgress = failedBatch ? `${t('states.archived')}: ${formatNumber(failedBatch.completed.length, i18n.resolvedLanguage ?? 'zh-CN')} / ${formatNumber(failedBatch.items.length, i18n.resolvedLanguage ?? 'zh-CN')}` : undefined

  return (
    <section className="identity-page announcement-page" aria-labelledby="announcement-management-title">
      {messageContext}
      <header className="announcement-heading">
        <h1 id="announcement-management-title">{t('title')}</h1>
      </header>
      <div className="identity-toolbar announcement-toolbar">
        <Select aria-label={t('filters.status')} value={status} onChange={(value: AnnouncementStatus | 'all') => { setStatus(value); setCursorStack([]); setSelectedRowKeys([]) }} options={[{ value: 'all', label: t('filters.all') }, ...(['draft', 'scheduled', 'published', 'withdrawn', 'archived'] as AnnouncementStatus[]).map((value) => ({ value, label: t(`states.${value}`) }))]} />
        <Button danger icon={<Trash2 size={15} />} disabled={selectedRowKeys.length === 0 || writesLocked} onClick={() => {
          const selected = items.filter((item) => selectedRowKeys.includes(item.id) && !item.archived)
          if (selected.length > 0) setConfirm({ action: 'archive-batch', items: selected })
        }}>{t('actions.deleteSelected')}</Button>
        <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => void openEditor(null, 'create')}>{t('actions.create')}</Button>
        <Button icon={<Check size={15} />} onClick={() => void listQuery.refetch()} loading={listQuery.isFetching}>{t('actions.refresh')}</Button>
      </div>
      {writeError && !uncertain ? <FeedbackWhen title={errorText(writeError, t)} detail={batchProgress} onClose={() => setWriteError(null)} /> : null}
      {listQuery.isError && !(listQuery.error instanceof ApiError && listQuery.error.code === 'permission_denied') ? <FeedbackWhen title={listError} action={<Button size="small" onClick={() => void listQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll announcement-table-scroll" data-testid="announcement-table-scroll" aria-busy={listQuery.isPending || listQuery.isFetching}>
        <Table<Announcement> rowKey="id" size="small" columns={columns} dataSource={items} loading={listQuery.isPending} pagination={false} locale={{ emptyText: listQuery.isError ? t('values.error') : t('values.empty') }} scroll={{ x: 1120 }} rowSelection={{ selectedRowKeys, onChange: (keys) => setSelectedRowKeys(keys.map(String)), getCheckboxProps: (item) => ({ disabled: item.archived }) }} />
      </div>
      <div className="identity-pagination announcement-pagination">
        <Button disabled={cursorStack.length === 0 || writesLocked} onClick={() => setCursorStack([])}>{t('actions.firstPage')}</Button>
        <Button disabled={cursorStack.length === 0 || writesLocked} onClick={() => setCursorStack((value) => value.slice(0, -1))}>{t('actions.previousPage')}</Button>
        <Button disabled={!listQuery.data?.next_cursor || writesLocked} onClick={() => listQuery.data?.next_cursor && setCursorStack((value) => [...value, listQuery.data!.next_cursor!])}>{t('actions.nextPage')}</Button>
        <span>{t('values.total', { count: formatNumber(items.length, i18n.resolvedLanguage ?? 'zh-CN') })}</span>
      </div>

      <Modal className="announcement-editor-modal" title={editor?.mode === 'revise' ? t('form.reviseTitle') : editor?.mode === 'edit' ? t('form.editTitle') : t('form.createTitle')} open={editor !== null} width={720} onCancel={uncertain ? closeAndRefresh : () => setEditor(null)} closable={!writesLocked} maskClosable={!writesLocked} footer={uncertain ? uncertainActions : [<Button key="cancel" onClick={() => setEditor(null)} disabled={writesLocked}>{t('actions.cancel')}</Button>, <Button key="submit" type="primary" aria-label={t('actions.save')} loading={mutation.isPending} disabled={writesLocked} onClick={() => void submit()}>{t('editorConfirm')}</Button>]} destroyOnHidden>
        {uncertain ? (
          <Alert className="identity-alert" type="warning" showIcon message={t('uncertainty.title')} description={t('uncertainty.description')} />
        ) : null}
        <Form form={form} layout="horizontal" className="announcement-compat-form" initialValues={{ format: 'content', sort_order: 100, visible: true, popup: false, red: false, bold: false, all: true, withdrawal_visibility: 'retain' }} disabled={writesLocked}>
          <div className="announcement-form-section"><h2><span />{t('form.basic')}</h2>
          <Form.Item name="format" noStyle><Input type="hidden" /></Form.Item>
          <Form.Item name="title" label={t('form.title')} rules={[{ required: true, whitespace: true, message: t('form.titleRequired') }, { validator: (_rule, value?: string) => {
            const valid = !value || Array.from(value).length <= 160
            return valid ? Promise.resolve() : Promise.reject(new Error(t('form.titleTooLong')))
          } }]}><Input placeholder={t('form.titlePlaceholder')} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.format !== next.format}>{({ getFieldValue }) => <Form.Item label={t('form.format')}><div className="announcement-format-switch"><Button type={getFieldValue('format') === 'content' ? 'primary' : 'default'} className="announcement-format-button" onClick={() => form.setFieldValue('format', 'content')} aria-pressed={getFieldValue('format') === 'content'}>{t('form.showContent')}</Button><Button type={getFieldValue('format') === 'link' ? 'primary' : 'default'} className="announcement-format-button" onClick={() => form.setFieldValue('format', 'link')} aria-pressed={getFieldValue('format') === 'link'}>{t('form.jumpLink')}</Button></div></Form.Item>}</Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.format !== next.format}>{({ getFieldValue }) => getFieldValue('format') === 'link' ? <Form.Item name="link_url" label={t('form.link')} rules={[{ required: true, whitespace: true, message: t('form.linkRequired') }]}><Input placeholder={t('form.linkPlaceholder')} /></Form.Item> : <Form.Item name="body" label={t('form.body')} rules={[{ required: true, whitespace: true, message: t('form.bodyRequired') }, { validator: (_rule, value?: string) => {
            const valid = !value || new TextEncoder().encode(value).byteLength <= 65536
            return valid ? Promise.resolve() : Promise.reject(new Error(t('form.bodyTooLong')))
          } }]}><Input.TextArea aria-label={t('form.bodyLegacy')} rows={10} maxLength={65536} placeholder={t('form.bodyPlaceholder')} /></Form.Item>}</Form.Item>
          <Form.Item name="sort_order" label={t('form.sort')} rules={[{ required: true, type: 'number', min: 0, max: 999999, message: t('form.sortRequired') }]}><InputNumber className="announcement-sort-input" controls={false} /></Form.Item>
          </div>
          <div className="announcement-form-section"><h2><span />{t('form.displayState')}</h2>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.visible !== next.visible}>{({ getFieldValue }) => <Form.Item name="visible" label={t('form.visible')} valuePropName="checked"><Space><Switch /><span>{getFieldValue('visible') ? t('form.alreadyVisible') : t('form.hidden')}</span></Space></Form.Item>}</Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.popup !== next.popup}>{({ getFieldValue }) => <Form.Item name="popup" label={t('form.popup')} valuePropName="checked"><Space><Switch /><span>{getFieldValue('popup') ? t('form.popupDisplay') : t('form.normalDisplay')}</span></Space></Form.Item>}</Form.Item>
          <Form.Item label={t('form.style')}><Space><Form.Item name="red" valuePropName="checked" noStyle><Checkbox>{t('form.red')}</Checkbox></Form.Item><Form.Item name="bold" valuePropName="checked" noStyle><Checkbox>{t('form.bold')}</Checkbox></Form.Item></Space></Form.Item>
          </div>
          {/* Audience is a reachable "advanced" section (C32), summarized while folded. */}
          <details className="announcement-advanced-audience">
          <summary><Form.Item noStyle shouldUpdate={(prev, next) => prev.all !== next.all}>{({ getFieldValue }) =>
            <span>{t('form.advancedAudience')}：{getFieldValue('all') ? t('form.allUsers') : t('form.selectedUsers')}</span>}</Form.Item></summary>
          <Form.Item name="all" label={t('form.audience')}><Select options={[{ value: true, label: t('form.allUsers') }, { value: false, label: t('form.selectedUsers') }]} /></Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, next) => prev.all !== next.all}>{({ getFieldValue }) => {
            if (getFieldValue('all')) return null
            return <>
              <Form.Item name="user_ids" label={t('form.users')}><AnnouncementAudienceSelect ariaLabel={t('form.users')} search={searchUsers} toOption={toAudienceOption} placeholder={t('form.searchUsers')} /></Form.Item>
              <Form.Item name="group_ids" label={t('form.roles')}><AnnouncementAudienceSelect ariaLabel={t('form.roles')} search={searchRoles} toOption={toAudienceOption} placeholder={t('form.searchRoles')} /></Form.Item>
            </>
          }}</Form.Item>
          <Form.Item name="withdrawal_visibility" label={t('form.withdrawalVisibility')}><Select options={[{ value: 'retain', label: t('form.retain') }, { value: 'hide', label: t('form.hide') }]} /></Form.Item>
          </details>
        </Form>
      </Modal>

      <Modal className="announcement-detail-modal" title={detail?.title ?? t('actions.view')} open={Boolean(detailID)} onCancel={() => setDetailID(null)} footer={<Button onClick={() => setDetailID(null)}>{t('actions.close')}</Button>} destroyOnHidden>
        {detailQuery.isPending ? (
          <Spin aria-label={t('values.loading')} />
        ) : detailQuery.isError ? (
          <Alert type="error" message={errorText(detailQuery.error, t)} action={<Button onClick={() => void detailQuery.refetch()}>{t('actions.retry')}</Button>} />
        ) : detail ? (
          <>
            <p className="announcement-detail-meta">{t(`states.${detail.status}`)} · {formatDateTime(detail.state_changed_at, i18n.resolvedLanguage ?? 'zh-CN') || detail.state_changed_at}</p>
            <pre className="announcement-body-preview cdnca-dialog-scroll">{detail.body}</pre>
          </>
        ) : null}
      </Modal>

      <Modal title={t('form.scheduleTitle')} open={Boolean(scheduleItem)} onCancel={uncertain ? closeAndRefresh : () => setScheduleItem(null)} okText={t('actions.schedule')} cancelText={t('actions.cancel')} confirmLoading={mutation.isPending} okButtonProps={{ disabled: writesLocked }} closable={!writesLocked} maskClosable={!writesLocked} footer={uncertain ? uncertainActions : undefined} onOk={() => {
        const parsed = new Date(publishAt)
        if (!publishAt || Number.isNaN(parsed.getTime()) || parsed.getTime() <= Date.now()) {
          setScheduleValidation(t('form.scheduleRequired'))
          return
        }
        if (scheduleItem) beginWrite({ action: 'schedule', item: scheduleItem, publish_at: parsed.toISOString() })
      }} destroyOnHidden>
        {uncertain ? <Alert className="identity-alert" type="warning" showIcon message={t('uncertainty.title')} description={t('uncertainty.description')} /> : null}
        {scheduleValidation ? <Alert type="error" showIcon message={scheduleValidation} /> : null}
        <Input aria-label={t('form.publishAt')} type="datetime-local" value={publishAt} onChange={(event) => { setScheduleValidation(null); setPublishAt(event.target.value) }} />
      </Modal>

      <Modal title={confirm?.action === 'publish' ? t('confirm.publishTitle') : confirm?.action === 'archive' || confirm?.action === 'archive-batch' ? t('confirm.archiveTitle') : confirm?.action === 'restore' ? t('confirm.restoreTitle') : t('confirm.withdrawTitle')} open={Boolean(confirm)} okText={t('actions.confirm')} cancelText={t('actions.cancel')} confirmLoading={mutation.isPending} okButtonProps={{ disabled: Boolean(publishItem) && (audienceCountQuery.data ?? 0) === 0 }} cancelButtonProps={{ disabled: mutation.isPending }} closable={!writesLocked} maskClosable={!writesLocked} footer={uncertain ? uncertainActions : undefined} onCancel={uncertain ? closeAndRefresh : () => setConfirm(null)} onOk={() => {
        if (confirm?.action === 'archive-batch') beginWrite({ action: 'archive-batch', items: confirm.items, completed: [] })
        else if (confirm) beginWrite({ action: confirm.action, item: confirm.item })
      }} destroyOnHidden>
        {uncertain ? <Alert className="identity-alert" type="warning" showIcon message={t('uncertainty.title')} description={t('uncertainty.description')} /> : null}
        {batchProgress ? <p>{batchProgress}</p> : null}
        {confirm?.action === 'publish' ? t('confirm.publishDescription') : confirm?.action === 'archive' || confirm?.action === 'archive-batch' ? t('confirm.archiveDescription') : confirm?.action === 'restore' ? t('confirm.restoreDescription') : t('confirm.withdrawDescription')}
        {publishItem ? <AudienceCountNotice loading={audienceCountQuery.isPending} error={audienceCountQuery.isError ? errorText(audienceCountQuery.error, t) : null} count={audienceCountQuery.data} onRetry={() => void audienceCountQuery.refetch()} /> : null}
      </Modal>
    </section>
  )
}
