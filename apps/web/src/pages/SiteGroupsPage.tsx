import { useEffect, useRef, useState } from 'react'
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Result, Select, Spin, Table, type TableColumnsType } from 'antd'
import { useFormSubmitError, useFeedbackMessage, useFeedback, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { Pencil, Plus, RotateCw, Trash2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { siteGroupsApi, type AdminSiteGroup, type SiteGroup } from '../api/siteGroups'
import { usersApi, type ManagedUser } from '../api/users'
import { useSessionStore } from '../auth/session'
import { clearSiteGroupRetry, persistSiteGroupRetry, restoreSiteGroupRetry, type SiteGroupAttempt, type SiteGroupRetry, type SiteGroupRetryOwner } from './siteGroupRetryRecord'
import './SiteGroupsPage.css'

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const staleSession = new ApiError('Session changed', 409, 'session_owner_changed')

function writeKey(action: string, id = 'new'): string {
  return `site-group-${action}-${id}-${crypto.randomUUID()}`
}

function owner(principal: Principal | null, epoch: number): string | null {
  if (!principal || !uuidPattern.test(principal.scope_id) || !uuidPattern.test(principal.user_id) || !epoch ||
    principal.scope_kind !== 'platform' && principal.scope_kind !== 'tenant' ||
    principal.scope_kind === 'tenant' && (!principal.tenant_id || !uuidPattern.test(principal.tenant_id))) return null
  return JSON.stringify([principal.scope_kind, principal.scope_id, principal.tenant_id, principal.user_id, epoch])
}

export default function SiteGroupsPage() {
  const { t } = useTranslation('siteGroups')
  const token = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const epoch = useSessionStore((state) => state.sessionEpoch)
  const status = useSessionStore((state) => state.status)
  const ownerKey = owner(principal, epoch)
  if (status !== 'authenticated' || !token || !principal || !principal.permissions.includes('sites.read') ||
    principal.scope_kind === 'platform' && !principal.permissions.includes('identity.users.manage')) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  if (!ownerKey) {
    return <Result status="info" title={t('errors.scopeRequiredTitle')} subTitle={t('errors.scopeRequiredDescription')} />
  }
  const permissionKey = JSON.stringify(['sites.read', 'sites.manage', 'identity.users.manage'].map((permission) => principal.permissions.includes(permission)))
  return <SiteGroupsScope key={`${ownerKey}:${permissionKey}`} ownerKey={ownerKey} principal={principal} />
}

function SiteGroupsScope({ ownerKey, principal }: { ownerKey: string; principal: Principal }) {
  const { t } = useTranslation('siteGroups')
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [selectedKeys, setSelectedKeys] = useState<React.Key[]>([])
  const [selectedUser, setSelectedUser] = useState<ManagedUser | null>(null)
  const [search, setSearch] = useState('')
  const [editor, setEditor] = useState<{ item?: SiteGroup } | null>(null)
  const [removeTargets, setRemoveTargets] = useState<SiteGroup[]>([])
  const [denied, setDenied] = useState(false)
  const retryOwner: SiteGroupRetryOwner = [principal.scope_kind as 'tenant' | 'platform', principal.scope_id, principal.user_id]
  const [initial] = useState(() => restoreSiteGroupRetry(retryOwner))
  const [journal, setJournal] = useState(initial.record)
  const journalRef = useRef(initial.record)
  const [blocked, setBlocked] = useState(initial.blocked)
  const [pending, setPending] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const inFlight = useRef(false)
  const draftGeneration = useRef(0)
  const [form] = Form.useForm<{ name: string; remark: string }>()
  const markSubmitError = useFormSubmitError(form)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const active = useRef(true)
  const deniedRef = useRef(false)
  const platform = principal.scope_kind === 'platform'
  const canManage = principal.permissions.includes('sites.manage')
  useEffect(() => {
    active.current = true
    return () => {
      active.current = false
      for (const prefix of ['site-groups', 'site-group-users']) {
        void queryClient.cancelQueries({ queryKey: [prefix, ownerKey] })
        queryClient.removeQueries({ queryKey: [prefix, ownerKey] })
      }
    }
  }, [ownerKey, queryClient])
  const sessionAccess = (permission: string, target?: string): string | null => {
    const session = useSessionStore.getState()
    if (!active.current || deniedRef.current || owner(session.principal, session.sessionEpoch) !== ownerKey ||
      session.status !== 'authenticated' || !session.principal?.permissions.includes('sites.read') ||
      !session.principal.permissions.includes(permission) || target !== undefined && (!uuidPattern.test(target) || !platform && target !== principal.scope_id) ||
      platform && !session.principal.permissions.includes('identity.users.manage')) return null
    return session.accessToken
  }
  const users = useInfiniteQuery({
    queryKey: ['site-group-users', ownerKey, search],
    enabled: platform && editor !== null && !editor.item && !denied && !journal,
    initialPageParam: 1,
    queryFn: async ({ pageParam }) => {
      const token = sessionAccess('identity.users.manage')
      if (!token) throw staleSession
      try {
        const result = await usersApi.list(token, { page: pageParam, limit: 20, search, status: 'active', role: 'tenant_owner' })
        if (!sessionAccess('identity.users.manage')) throw staleSession
        return result
      } catch (error) {
        if (sessionAccess('identity.users.manage') && error instanceof ApiError && error.status === 403) {
          deniedRef.current = true
          setDenied(true)
        }
        throw error
      }
    },
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const userOptions = users.data?.pages.flatMap((result) => result.items).filter((item) => item.status === 'active' && item.role === 'tenant_owner') ?? []
  const queryKey = ['site-groups', ownerKey, page, limit] as const
  const readGroups = async () => {
    const token = sessionAccess('sites.read')
    if (!token) throw staleSession
    try {
      const result = platform ? await siteGroupsApi.listAdmin(token, page, limit) : await siteGroupsApi.list(token, principal.scope_id, page, limit)
      if (!sessionAccess('sites.read')) throw staleSession
      return result
    } catch (error) {
      if (sessionAccess('sites.read') && error instanceof ApiError && error.status === 403) {
        deniedRef.current = true
        setDenied(true)
      }
      throw error
    }
  }
  const query = useQuery({
    queryKey,
    enabled: !denied,
    queryFn: readGroups,
    retry: false,
  })
  const remember = (next: SiteGroupRetry): boolean => {
    if (!persistSiteGroupRetry(next, journalRef.current)) { setBlocked(true); return false }
    journalRef.current = next
    setJournal(next)
    return true
  }
  const finish = (): boolean => {
    if (!journalRef.current || !clearSiteGroupRetry(journalRef.current)) { setBlocked(true); return false }
    journalRef.current = null
    setJournal(null)
    return true
  }
  const runJournal = async (allowWrites: boolean) => {
    if (inFlight.current || blocked || !journalRef.current || !sessionAccess(allowWrites ? 'sites.manage' : 'sites.read')) return
    inFlight.current = true
    setPending(true)
    setNotice(null)
    let superseded = journalRef.current.items.some((item) => item.superseded)
    try {
      for (let index = 0; index < journalRef.current.items.length; index += 1) {
        let input = journalRef.current.items[index]
        if (input.phase === 'done') continue
        if (input.phase === 'ready' || input.phase === 'unknown') {
          if (!allowWrites) return
          const token = sessionAccess('sites.manage', input.scope)
          if (!token) return
          const wasUnknown = input.phase === 'unknown'
          if (!remember({ ...journalRef.current, items: journalRef.current.items.map((item, i) => i === index ? { ...item, phase: 'unknown' } : item) })) return
          input = journalRef.current.items[index]
          try {
            const target = { id: input.id!, scope_id: input.scope, revision: input.revision! } as SiteGroup
            const saved = input.action === 'create' ? await siteGroupsApi.create(token, input.scope, input.name!, input.key, input.remark)
              : input.action === 'rename' ? await siteGroupsApi.rename(token, target, input.name!, input.key, input.remark)
                : await siteGroupsApi.remove(token, target, input.key)
            if (!sessionAccess('sites.manage', input.scope)) return
            if (saved && (saved.scope_id !== input.scope || saved.deleted_at || saved.name !== input.name ||
              saved.remark !== undefined && saved.remark !== input.remark ||
              (input.action === 'create' ? saved.revision !== 1 : saved.id !== input.id || saved.revision !== input.revision && saved.revision !== input.revision! + 1))) throw new ApiError('Invalid group acknowledgement', 502, 'invalid_response')
            const accepted = saved ? { id: saved.id, revision: saved.revision, name: saved.name, ...(saved.remark === undefined ? {} : { remark: saved.remark }) } : undefined
            if (!remember({ ...journalRef.current, items: journalRef.current.items.map((item, i) => i === index ? { ...item, phase: 'accepted', ...(accepted ? { accepted } : {}) } : item) })) return
          } catch (error) {
            if (!sessionAccess('sites.manage', input.scope)) return
            if (error instanceof ApiError && error.status === 403) { deniedRef.current = true; setDenied(true); return }
            if (wasUnknown || !(error instanceof ApiError) || error.status >= 500 || error.status === 0 || error.status === 408 || error.code === 'invalid_response') return
            if (!finish()) return
            // fix-fielderr-be4: a refused name/remark of the open editor is marked under its box.
            if (input.action !== 'delete' && markSubmitError(error)) return
            feedback.error(t(error.code === 'site_group_in_use' ? 'errors.inUse' : 'errors.write'))
            return
          }
          input = journalRef.current.items[index]
        }
        const token = sessionAccess('sites.read', input.scope)
        if (!token) return
        try {
          const current = await siteGroupsApi.get(token, input.scope, input.accepted?.id ?? input.id!)
          if (!sessionAccess('sites.read', input.scope)) return
          if (input.action === 'delete' || !input.accepted || current.revision < input.accepted.revision ||
            current.revision === input.accepted.revision && (current.name !== input.name || current.remark !== input.remark)) throw new ApiError('Readback mismatch', 502, 'invalid_response')
          superseded ||= current.revision > input.accepted.revision
        } catch (error) {
          if (!sessionAccess('sites.read', input.scope)) return
          if (!(input.action === 'delete' && error instanceof ApiError && error.status === 404 && error.code === 'not_found')) throw error
        }
        if (!remember({ ...journalRef.current, items: journalRef.current.items.map((item, i) => i === index ? { ...item, phase: 'done', ...(superseded ? { superseded: true as const } : {}) } : item) })) return
      }
      await query.refetch({ throwOnError: true })
      if (!sessionAccess('sites.read')) return
      if (finish()) {
        setEditor(null)
        setRemoveTargets([])
        setSelectedKeys([])
        messageApi[ superseded ? 'warning' : 'success' ](t(superseded ? 'messages.superseded' : 'messages.saved'))
      }
    } catch (error) {
      if (!sessionAccess('sites.read')) return
      if (error instanceof ApiError && error.status === 403) { deniedRef.current = true; setDenied(true) }
      else setNotice('errors.readback')
    } finally {
      inFlight.current = false
      if (active.current) setPending(false)
    }
  }
  const submitGroup = (inputs: Omit<SiteGroupAttempt, 'key' | 'phase'>[]) => {
    if (inFlight.current || blocked || journalRef.current || !inputs.length || inputs.some((input) => !sessionAccess('sites.manage', input.scope))) return
    const record: SiteGroupRetry = { version: 1, owner: retryOwner, items: inputs.map((input) => ({ ...input, key: writeKey(input.action, input.id), phase: 'ready' })) }
    if (remember(record)) void runJournal(true)
  }
  if (denied) {
    return <Result status="403" title={t('errors.forbiddenTitle')} subTitle={t('errors.forbiddenDescription')} />
  }
  const writeLocked = pending || Boolean(journal) || blocked
  const items = !query.isError ? query.data?.items ?? [] : []
  const nextAttempt = journal?.items.find((item) => item.phase !== 'done')
  const readOnlyRetry = !nextAttempt || nextAttempt.phase === 'accepted'
  const retryPanel = blocked ? <Alert type="error" showIcon message={t('errors.storage')} /> : journal ?
    <OutcomeUnknown title={t(notice ?? (readOnlyRetry ? 'errors.readback' : nextAttempt?.phase === 'unknown' ? 'errors.unknown' : 'errors.continueBatch'))} action={<Button size="small" loading={pending} disabled={!readOnlyRetry && !canManage} onClick={() => void runJournal(!readOnlyRetry)}>{t(readOnlyRetry ? 'actions.retryRead' : nextAttempt?.phase === 'unknown' ? 'actions.retryWrite' : 'actions.continueBatch')}</Button>} /> : null
  const columns: TableColumnsType<SiteGroup> = [
    { title: t('columns.id'), dataIndex: 'display_id', width: 90, render: (value?: string) => value ?? t('unknownValue') },
    ...(platform ? [{ title: t('columns.user'), key: 'user', render: (_: unknown, value: SiteGroup) => {
      const item = value as AdminSiteGroup
      return item.user_state === 'resolved' ? `${item.user!.username}（${item.user!.display_id}）` : t(`scope.${item.user_state}`)
    } }] : []),
    { title: t('columns.name'), dataIndex: 'name' },
    { title: t('columns.remark'), dataIndex: 'remark', render: (value?: string) => <span className="site-groups-remark">{value === undefined ? t('unknownValue') : value}</span> },
    {
      title: t('columns.actions'), key: 'actions', width: 150,
      render: (_: unknown, item: SiteGroup) => <div className="site-groups-actions">
        <Button type="link" size="small" icon={<Pencil size={14} />} disabled={!canManage || writeLocked || item.remark === undefined} onClick={() => { draftGeneration.current += 1; form.setFieldsValue({ name: item.name, remark: item.remark }); setEditor({ item }) }}>{t('actions.rename')}</Button>
        <Button type="link" danger size="small" icon={<Trash2 size={14} />} disabled={!canManage || writeLocked} onClick={() => setRemoveTargets([item])}>{t('actions.delete')}</Button>
      </div>,
    },
  ]

  return <section className="site-groups-page site-groups-embedded" aria-label={t('title')}>
    {messageContext}
    <div className="site-groups-toolbar">
      <Button type="primary" icon={<Plus size={14} />} disabled={!canManage || writeLocked} onClick={() => { draftGeneration.current += 1; setSelectedUser(null); setSearch(''); form.resetFields(); setEditor({}) }}>{t('actions.create')}</Button>
      <Button icon={<RotateCw size={13} />} disabled={pending} loading={query.isFetching} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
      <Button danger icon={<Trash2 size={13} />} disabled={!canManage || writeLocked || !selectedKeys.length || query.isFetching || query.isError} onClick={() => setRemoveTargets(items.filter((item) => selectedKeys.includes(`${item.scope_id}:${item.id}`)))}>{t('actions.delete')}</Button>
      <span className="site-groups-count">{query.data && !query.isError ? t('pagination.total', { count: query.data.total }) : t('unknownValue')}</span>
    </div>
    {!editor && !removeTargets.length ? retryPanel : null}
    {query.isError ? <FeedbackWhen title={t('errors.read')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
    <Table rowKey={(item) => `${item.scope_id}:${item.id}`} size="small" loading={query.isFetching} columns={columns} dataSource={items}
      scroll={{ x: 720 }} tableLayout="fixed" rowSelection={{ selectedRowKeys: selectedKeys, onChange: (keys) => setSelectedKeys(keys), columnWidth: 48, getCheckboxProps: () => ({ disabled: !canManage || writeLocked }) }}
      pagination={{ current: page, pageSize: limit, total: !query.isError ? query.data?.total ?? 0 : 0, showSizeChanger: true, pageSizeOptions: [10, 20, 50, 100],
        showTotal: (total) => t('pagination.total', { count: total }), disabled: writeLocked || query.isFetching,
        onChange: (next, size) => { setSelectedKeys([]); setPage(size !== limit ? 1 : next); setLimit(size) } }} locale={{ emptyText: query.isPending ? ' ' : t('empty') }} />
    <Modal className="site-groups-editor" width={560} open={Boolean(editor)} title={editor?.item ? t('editor.renameTitle') : t('editor.createTitle')} okText={t('actions.save')} cancelText={t('actions.cancel')} confirmLoading={pending}
      okButtonProps={{ disabled: writeLocked || platform && !editor?.item && !selectedUser }}
      closable={!writeLocked} maskClosable={!writeLocked} keyboard={!writeLocked} cancelButtonProps={{ disabled: writeLocked }}
      onCancel={() => { if (!writeLocked) { draftGeneration.current += 1; setEditor(null) } }} onOk={() => {
        const generation = draftGeneration.current
        void form.validateFields().then((values) => {
          if (!editor || generation !== draftGeneration.current || writeLocked) return
          const scope = editor.item?.scope_id ?? (platform ? selectedUser?.scope_id : principal.scope_id)
          if (!scope || platform && !editor.item && !userOptions.some((item) => item.id === selectedUser?.id && item.scope_id === scope)) return
          submitGroup([{ action: editor.item ? 'rename' : 'create', scope, name: values.name.trim(), remark: values.remark ?? '',
            ...(editor.item ? { id: editor.item.id, revision: editor.item.revision } : {}) }])
        }).catch(() => undefined)
      }}>
      {retryPanel}
      <Form form={form} layout="horizontal" labelCol={{ flex: '90px' }} wrapperCol={{ flex: 1 }} initialValues={{ remark: '' }}>
        {platform && !editor?.item ? <Form.Item label={t('scope.user')}>
          <Select aria-label={t('scope.user')} showSearch allowClear filterOption={false} value={selectedUser?.id}
            placeholder={t('scope.placeholder')} loading={users.isFetching} disabled={writeLocked}
            onChange={(id) => { draftGeneration.current += 1; setSelectedUser(userOptions.find((item) => item.id === id) ?? null) }}
            onSearch={(value) => { if (!writeLocked) { draftGeneration.current += 1; setSelectedUser(null); setSearch(value) } }}
            options={userOptions.map((item) => ({ value: item.id, label: `${item.username}（${item.display_id}）` }))}
            notFoundContent={users.isFetching ? <Spin size="small" /> : t('scope.empty')}
            popupRender={(menu) => <>{menu}{users.hasNextPage ? <Button block loading={users.isFetchingNextPage} onClick={() => void users.fetchNextPage()}>{t('scope.more')}</Button> : null}</>} />
          {users.isError ? <Alert type="error" showIcon message={t('scope.failed')} action={<Button size="small" onClick={() => void users.refetch()}>{t('actions.retry')}</Button>} /> : null}
        </Form.Item> : null}
        <Form.Item name="name" label={t('editor.name')} rules={[{ required: true, whitespace: true, message: t('editor.nameRequired') }, { max: 128, message: t('editor.nameTooLong') }]}><Input autoFocus maxLength={128} disabled={writeLocked} placeholder={t('editor.namePlaceholder')} /></Form.Item>
        <Form.Item name="remark" label={t('editor.remark')} rules={[{ max: 1024, message: t('editor.remarkTooLong') }]}><Input.TextArea rows={3} maxLength={1024} disabled={writeLocked} placeholder={t('editor.remarkPlaceholder')} /></Form.Item>
      </Form>
    </Modal>
    <Modal open={removeTargets.length > 0} title={t('delete.title')} okText={t('actions.delete')} okButtonProps={{ danger: true, disabled: writeLocked }} cancelText={t('actions.cancel')} confirmLoading={pending}
      closable={!writeLocked} maskClosable={!writeLocked} keyboard={!writeLocked} cancelButtonProps={{ disabled: writeLocked }}
      onCancel={() => { if (!writeLocked) setRemoveTargets([]) }} onOk={() => submitGroup(removeTargets.map((item) => ({ action: 'delete', id: item.id, revision: item.revision, scope: item.scope_id })))}>
      {retryPanel}
      <p>{t('delete.description', { name: removeTargets.map((item) => item.name).join('、') })}</p>
    </Modal>
  </section>
}
