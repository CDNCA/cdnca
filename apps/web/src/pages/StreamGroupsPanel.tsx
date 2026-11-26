import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Select, Space, type TableColumnsType } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown, Pagination, Table } from '@cdnca/ui'
import { Plus, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'

import { ApiError, type ScopeKind } from '../api/auth'
import { localizedUnknownApiError } from '../i18n/apiError'
import {
  streamGroupsApi,
  type CreateStreamGroupRequest,
  type StreamGroup,
  type StreamGroupFields,
} from '../api/streamGroups'
import { usersApi, type ManagedUser } from '../api/users'
import { ResourceID } from '../components/ResourceID'
import { useSessionStore } from '../auth/session'
import { hasStreamReadPermission, writeKey } from './streamForm'
import { useStreamPanelWrites } from './StreamGroupsState'
import '../i18n/streamPanels'
import '../i18n/unconfirmedClose'
import { useNamedRowSelection } from '../components/namedRowSelection'

interface GroupFormValues extends StreamGroupFields {
  owner_id?: string
}

// 分组弹窗的按钮顺序：先「取消」再「确定」。
export function streamGroupOwnerText(group: StreamGroup, unavailable: string): string {
  return group.owner?.display_name ?? unavailable
}

function sessionMatches(scopeKind: ScopeKind, scopeID: string, sessionEpoch: number): boolean {
  const current = useSessionStore.getState()
  return current.sessionEpoch === sessionEpoch &&
    current.principal?.scope_kind === scopeKind &&
    current.principal.scope_id === scopeID
}

function canManage(scopeKind: ScopeKind, scopeID: string, sessionEpoch: number): boolean {
  const permissions = useSessionStore.getState().principal?.permissions
  return sessionMatches(scopeKind, scopeID, sessionEpoch) &&
    Boolean(permissions?.includes('streams.manage') || permissions?.includes('platform.admin'))
}

function canRead(scopeKind: ScopeKind, scopeID: string, sessionEpoch: number): boolean {
  const permissions = useSessionStore.getState().principal?.permissions
  return sessionMatches(scopeKind, scopeID, sessionEpoch) && Boolean(permissions && hasStreamReadPermission(scopeKind, permissions))
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const staleGroupRead = new Error('stale group read')

function groupErrorMessage(error: ApiError, t: TFunction<'streams'>): string {
  return error.code === 'version_conflict'
    ? t('groups.version_conflict')
    : localizedUnknownApiError(error, t('errors.operationFailed'))
}

export default function StreamGroupsPanel({
  accessToken,
  scopeKind,
  scopeID,
  sessionEpoch,
  isAdmin,
  canManageGroups,
  lockWrites,
}: {
  accessToken: string
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  isAdmin: boolean
  canManageGroups: boolean
  lockWrites: boolean
}) {
  const { t } = useTranslation('streams')
  const { t: tp } = useTranslation('streamPanels')
  const { t: tu } = useTranslation('unconfirmedClose')
  const namedRows = useNamedRowSelection()
  const queryClient = useQueryClient()
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const [messageApi, messageContext] = useFeedbackMessage()
  const [modalApi, modalContext] = Modal.useModal()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [modalOpen, setModalOpen] = useState(false)
  // 行内「编辑」改名称与备注，带 If-Match 的 PATCH；版本冲突提示并刷新。
  const [editing, setEditing] = useState<StreamGroup>()
  const [editPending, setEditPending] = useState(false)
  const [form] = Form.useForm<GroupFormValues>()
  const modalOpenRef = useRef(false)
  modalOpenRef.current = modalOpen

  const query = useQuery({
    queryKey: ['stream-groups', scopeKind, scopeID, sessionEpoch, page, limit],
    queryFn: async () => {
      if (!canRead(scopeKind, scopeID, sessionEpoch)) throw staleGroupRead
      const response = await streamGroupsApi.listGroups(accessTokenRef.current, { page, limit })
      if (!canRead(scopeKind, scopeID, sessionEpoch)) throw staleGroupRead
      return response
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  const canReadOwners = () => canManage(scopeKind, scopeID, sessionEpoch) && canRead(scopeKind, scopeID, sessionEpoch) &&
    Boolean(useSessionStore.getState().principal?.permissions.some((permission) =>
      ['identity.users.manage', 'platform.admin'].includes(permission)))
  const ownerQuery = useQuery({
    queryKey: ['stream-panel-owner-options', scopeKind, scopeID, sessionEpoch],
    queryFn: async () => {
      const items: ManagedUser[] = []
      for (let ownerPage = 1; ; ownerPage += 1) {
        if (!canReadOwners()) throw staleGroupRead
        const response = await usersApi.list(accessTokenRef.current, { page: ownerPage, limit: 100 })
        if (!canReadOwners()) throw staleGroupRead
        items.push(...response.items)
        if (ownerPage * response.limit >= response.total || response.items.length === 0) return items
      }
    },
    enabled: isAdmin && modalOpen && !editing && canReadOwners(),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  useEffect(() => {
    if (!canManageGroups) {
      setModalOpen(false)
      setSelectedRowKeys([])
    }
  }, [canManageGroups])

  // A group write changes what forwarding rows, details, defaults and the group
  // pickers of this scope/owner show, so all of them are read again.
  const invalidate = () => Promise.all([
    'stream-groups', 'streams', 'stream-detail', 'stream-user-configs', 'stream-default-group-options', 'stream-form-group-options', 'stream-filter-options',
  ].map((key) => queryClient.invalidateQueries({ queryKey: [key, scopeKind, scopeID, sessionEpoch] })))

  const forbidden = query.error instanceof ApiError && query.error.status === 403
  const writes = useStreamPanelWrites<CreateStreamGroupRequest, StreamGroup>({
    sameSession: () => sessionMatches(scopeKind, scopeID, sessionEpoch),
    canWrite: () => canManage(scopeKind, scopeID, sessionEpoch) && canRead(scopeKind, scopeID, sessionEpoch) && !forbidden,
    blocked: lockWrites || query.isFetching,
    recoveryKey: ['stream-group-recovery', scopeKind, scopeID, sessionEpoch],
    create: (input, key) => streamGroupsApi.createGroup(accessTokenRef.current, input, key),
    remove: (item, key) => streamGroupsApi.removeGroup(accessTokenRef.current, item, key),
    invalidate,
    created: () => { setModalOpen(false); messageApi.success(t('groups.created')) },
    deleted: (failedIDs) => {
      setSelectedRowKeys(failedIDs)
      if (failedIDs.length === 0) messageApi.success(t('groups.deleted'))
    },
  })
  const pending = writes.pending
  const writeError = writes.error
  const writesLocked = lockWrites || pending || editPending || writes.uncertain || query.isFetching || forbidden
  const ownerUnavailable = isAdmin && !editing && (!canReadOwners() || ownerQuery.isError || ownerQuery.isFetching || !ownerQuery.data)

  useEffect(() => { if (writes.uncertain) setModalOpen(false) }, [writes.uncertain])
  useEffect(() => () => {
    if (!canRead(scopeKind, scopeID, sessionEpoch)) {
      queryClient.removeQueries({ queryKey: ['stream-groups', scopeKind, scopeID, sessionEpoch] })
      queryClient.removeQueries({ queryKey: ['stream-panel-owner-options', scopeKind, scopeID, sessionEpoch] })
    }
  }, [queryClient, scopeKind, scopeID, sessionEpoch])
  useEffect(() => {
    if (query.data && !query.isFetching && page > 1 && query.data.total <= (page - 1) * limit) {
      setPage(Math.max(1, Math.ceil(query.data.total / limit)))
    }
  }, [query.data, query.isFetching, page, limit])

  const selectedGroups = (query.data?.items ?? []).filter((item) => selectedRowKeys.includes(item.id))

  // The dialog names what is deleted: the group (or how many) and the real
  // number of forwarding rules that reference it.
  const confirmDelete = (groups: StreamGroup[]) => {
    if (groups.length === 0) return
    const single = groups.length === 1 ? groups[0] : undefined
    const references = groups.reduce((total, group) => total + group.stream_count, 0)
    modalApi.confirm({
      title: single ? t('groups.deleteTitle', { name: single.name }) : t('groups.deleteTitleMany', { count: groups.length }),
      content: references > 0
        ? t(single ? 'groups.deleteReferences' : 'groups.deleteReferencesMany', { count: references })
        : t(single ? 'groups.deleteNoReferences' : 'groups.deleteNoReferencesMany'),
      okText: t('actions.confirmDelete'),
      okButtonProps: { danger: true, 'aria-label': single ? t('groups.deleteConfirmNamed', { name: single.name }) : t('groups.deleteConfirmMany', { count: groups.length }) },
      cancelText: t('actions.cancel'),
      onOk: () => {
        if (!canManage(scopeKind, scopeID, sessionEpoch)) return
        writes.remove(groups)
      },
    })
  }

  const columns: TableColumnsType<StreamGroup> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 78,
      render: (_: string, item) => <>
        <ResourceID internalId={item.id} displayId={item.display_id} />
        <span className="visually-hidden">{item.name}</span>
      </>,
    },
    // 普通租户只看自己的分组，不显示用户列；管理员跨用户查看才需要
    ...(isAdmin ? [{
      title: t('groups.user'), key: 'owner', width: 180,
      render: (_: unknown, item: StreamGroup) => <span className={item.owner ? undefined : 'stream-unavailable'}>
        {streamGroupOwnerText(item, t('values.unavailable'))}
      </span>,
    }] : []),
    { title: t('groups.name'), dataIndex: 'name', key: 'name' },
    {
      title: t('groups.remark'), key: 'remark',
      render: (_, item) => item.remark || <span className="stream-unavailable">{t('values.placeholder')}</span>,
    },
    {
      title: t('columns.actions'), key: 'actions', width: 118, fixed: 'right',
      render: (_, item) => <Space size={0}>
        {canManageGroups ? <Button
          type="link"
          size="small"
          aria-label={t('groups.editNamed', { name: item.name })}
          disabled={writesLocked}
          onClick={() => openEdit(item)}
        >
          {t('groups.edit')}
        </Button> : null}
        <Button
          type="link"
          size="small"
          danger
          disabled={!canManageGroups || writesLocked}
          onClick={() => confirmDelete([item])}
        >
          {t('groups.delete')}
        </Button>
      </Space>,
    },
  ]

  const openEdit = (item: StreamGroup) => {
    writes.clearError()
    setEditing(item)
    form.setFieldsValue({ name: item.name, remark: item.remark })
    setModalOpen(true)
  }

  const saveEdit = async (item: StreamGroup, values: GroupFormValues) => {
    setEditPending(true)
    try {
      await streamGroupsApi.updateGroup(accessTokenRef.current, item.id, {
        name: values.name.trim(), remark: (values.remark ?? '').trim(), expected_revision: item.revision,
      }, writeKey('stream-group-update'))
      if (!sessionMatches(scopeKind, scopeID, sessionEpoch)) return
      setModalOpen(false)
      setEditing(undefined)
      messageApi.success(t('groups.updated'))
      await invalidate()
    } catch (error) {
      if (!sessionMatches(scopeKind, scopeID, sessionEpoch)) return
      if (error instanceof ApiError && error.code === 'version_conflict') {
        setModalOpen(false)
        setEditing(undefined)
        messageApi.error(t('groups.editConflict'))
        await invalidate()
        return
      }
      messageApi.error(error instanceof ApiError ? groupErrorMessage(error, t) : t('errors.requestFailed'))
    } finally {
      setEditPending(false)
    }
  }

  const submit = (values: GroupFormValues) => {
    if (!canManageGroups || writesLocked || ownerUnavailable || !canManage(scopeKind, scopeID, sessionEpoch)) return
    if (editing) {
      void saveEdit(editing, values)
      return
    }
    const owner = isAdmin ? ownerQuery.data?.find((user) => user.id === values.owner_id) : undefined
    if (isAdmin && !owner) return
    writes.create({
      name: values.name.trim(),
      remark: (values.remark ?? '').trim(),
      ...(owner ? { owner_id: owner.id, target_scope_id: owner.scope_id } : {}),
    })
  }

  return (
    <>
      {messageContext}
      {modalContext}
      <div className="stream-panel-toolbar stream-groups-toolbar">
        <div className="stream-toolbar-actions">
          {canManageGroups ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => { writes.clearError(); setEditing(undefined); form.resetFields(); setModalOpen(true) }}>{t('groups.add')}</Button> : null}
          <Button icon={<RefreshCw size={15} />} loading={query.isFetching} onClick={() => void query.refetch()}>{t('actions.refresh')}</Button>
          {canManageGroups ? <Button disabled={writesLocked || selectedGroups.length === 0} onClick={() => confirmDelete(selectedGroups)}>{t('groups.delete')}</Button> : null}
        </div>
      </div>

      {writes.uncertain ? <OutcomeUnknown className="identity-alert" title={tp('unknown')} detail={tp('unknownDescription')} action={<Space size={4}><Button size="small" disabled={pending} onClick={writes.abandon}>{tu('abandonRefresh')}</Button>{canManageGroups ? <Button size="small" loading={pending} disabled={pending || lockWrites || query.isFetching || forbidden} onClick={writes.retry}>{tp('retryExact')}</Button> : null}</Space>} /> : writeError ? <FeedbackWhen title={t('groups.writeFailed')} detail={groupErrorMessage(writeError, t)} onClose={writes.clearError} /> : null}
      {query.isError ? <FeedbackWhen title={t('groups.listFailed')} detail={query.error instanceof ApiError ? groupErrorMessage(query.error, t) : t('errors.requestFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll" data-testid="stream-group-table-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table<StreamGroup>
          rowKey="id"
          size="small"
          rowSelection={canManageGroups ? namedRows<StreamGroup>({ selectedRowKeys, onChange: (keys) => setSelectedRowKeys(keys.map(String)) }, (group) => group.name, t('selectionScope.groups')) : undefined}
          columns={columns}
          dataSource={forbidden ? [] : query.data?.items ?? []}
          loading={query.isPending || query.isFetching}
          pagination={false}
          scroll={{ x: 720 }}
          locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }}
        />
      </div>
      <Pagination className="identity-pagination" current={page} pageSize={limit} total={query.data?.total ?? 0} pageSizeOptions={[10, 20, 50, 100]} showSizeChanger showTotal={(count) => t('values.total', { count })} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />

      <Modal
        className="identity-modal stream-modal"
        title={editing ? t('groups.editTitle') : t('groups.addTitle')}
        open={canManageGroups && modalOpen}
        onCancel={() => { if (writesLocked) return; setModalOpen(false); setEditing(undefined) }}
        onOk={() => form.submit()}
        confirmLoading={pending || editPending}
        okText={t('actions.confirm')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ disabled: writesLocked || ownerUnavailable }}
        destroyOnHidden
      >
        {isAdmin && !editing && (!canReadOwners() || ownerQuery.isError) ? <Alert className="identity-alert" type="error" showIcon message={tp(canReadOwners() ? 'ownersFailed' : 'ownersForbidden')} action={canReadOwners() ? <Button size="small" onClick={() => void ownerQuery.refetch()}>{t('actions.retry')}</Button> : undefined} /> : null}
        <Form form={form} disabled={pending || editPending} layout="horizontal" labelCol={{ flex: '88px' }} wrapperCol={{ flex: 1 }} requiredMark={false} onFinish={submit}>
          {/* 普通租户的归属由服务端会话决定，不显示用户字段 */}
          {isAdmin && !editing ? <Form.Item name="owner_id" label={t('groups.user')} rules={[
            { required: true, message: t('groups.userRequired') },
            { pattern: uuidPattern, message: t('groups.userInvalid') },
          ]}>
            <Select
              showSearch
              optionFilterProp="label"
              placeholder={t('groups.user')}
              loading={ownerQuery.isFetching}
              disabled={ownerUnavailable}
              options={(ownerQuery.data ?? []).map((user) => ({ value: user.id, label: user.display_name || user.username }))}
            />
          </Form.Item> : null}
          <Form.Item name="name" label={t('groups.name')} rules={[
            { required: true, whitespace: true, message: t('groups.nameRequired') },
            { max: 128, message: t('groups.nameTooLong') },
          ]}>
            <Input placeholder={t('groups.namePlaceholder')} />
          </Form.Item>
          <Form.Item name="remark" label={t('groups.remark')} rules={[{ max: 256, message: t('groups.remarkTooLong') }]}>
            <Input placeholder={t('groups.remarkPlaceholder')} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  )
}
