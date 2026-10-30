import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, Modal, Pagination, Radio, Select, Table, type TableColumnsType } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'

import { ApiError, type ScopeKind } from '../api/auth'
import { localizedUnknownApiError } from '../i18n/apiError'
import type { StreamSettingName, StreamSettingScope } from '../api/streams'
import {
  streamGroupsApi,
  type CreateStreamUserConfigRequest,
  type StreamGroup,
  type StreamUserConfig,
} from '../api/streamGroups'
import { usersApi, type ManagedUser } from '../api/users'
import { ResourceID } from '../components/ResourceID'
import { useSessionStore } from '../auth/session'
import { hasStreamReadPermission } from './streamForm'
import { useStreamPanelWrites } from './StreamGroupsState'
import '../i18n/streamPanels'

interface DefaultFormValues {
  owner_id?: string
  setting_name: StreamSettingName
  setting_value: string
  scope_name: StreamSettingScope
  group_id?: string
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const staleDefaultRead = new Error('stale default read')

const SETTING_NAMES: StreamSettingName[] = ['listen_protocol', 'balance_way', 'proxy_protocol']

// 设置项的取值集合固定，用下拉与单选呈现这组枚举。
const SETTING_VALUES: Record<StreamSettingName, string[]> = {
  listen_protocol: ['tcp', 'udp'],
  balance_way: ['rr', 'ip_hash'],
  proxy_protocol: ['1', '0'],
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

function defaultErrorMessage(error: ApiError, t: TFunction<'streams'>): string {
  return error.code === 'version_conflict'
    ? t('groups.version_conflict')
    : localizedUnknownApiError(error, t('errors.operationFailed'))
}

export default function StreamDefaultsPanel({
  accessToken,
  scopeKind,
  scopeID,
  sessionEpoch,
  isAdmin,
  canManageDefaults,
  lockWrites,
}: {
  accessToken: string
  scopeKind: ScopeKind
  scopeID: string
  sessionEpoch: number
  isAdmin: boolean
  canManageDefaults: boolean
  lockWrites: boolean
}) {
  const { t } = useTranslation('streams')
  const { t: tp } = useTranslation('streamPanels')
  const queryClient = useQueryClient()
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const [messageApi, messageContext] = useFeedbackMessage()
  const [modalApi, modalContext] = Modal.useModal()
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([])
  const [modalOpen, setModalOpen] = useState(false)
  const [form] = Form.useForm<DefaultFormValues>()
  const settingName = Form.useWatch('setting_name', form)
  const scopeName = Form.useWatch('scope_name', form)
  const ownerID = Form.useWatch('owner_id', form)

  const settingNameOptions = SETTING_NAMES.map((name) => ({
    value: name,
    label: name === 'listen_protocol'
      ? t('defaults.settingListenProtocol')
      : name === 'balance_way' ? t('defaults.settingBalanceWay') : t('defaults.settingProxyProtocol'),
  }))

  const settingValueLabel = (name: StreamSettingName, value: string): string => {
    if (name === 'listen_protocol') return value === 'udp' ? t('defaults.valueUDP') : t('defaults.valueTCP')
    if (name === 'balance_way') return value === 'ip_hash' ? t('defaults.valueIPHash') : t('defaults.valueRoundRobin')
    return value === '1' ? t('defaults.valueEnabled') : t('defaults.valueDisabled')
  }

  const query = useQuery({
    queryKey: ['stream-user-configs', scopeKind, scopeID, sessionEpoch, page, limit],
    queryFn: async () => {
      if (!canRead(scopeKind, scopeID, sessionEpoch)) throw staleDefaultRead
      const response = await streamGroupsApi.listUserConfigs(accessTokenRef.current, { page, limit })
      if (!canRead(scopeKind, scopeID, sessionEpoch)) throw staleDefaultRead
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
        if (!canReadOwners()) throw staleDefaultRead
        const response = await usersApi.list(accessTokenRef.current, { page: ownerPage, limit: 100 })
        if (!canReadOwners()) throw staleDefaultRead
        items.push(...response.items)
        if (ownerPage * response.limit >= response.total || response.items.length === 0) return items
      }
    },
    enabled: isAdmin && modalOpen && canReadOwners(),
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  const selectedOwner = ownerQuery.data?.find((owner) => owner.id === ownerID)
  const targetScopeID = isAdmin ? selectedOwner?.scope_id : scopeID
  const targetOwnerID = isAdmin ? selectedOwner?.id : useSessionStore.getState().principal?.user_id
  const groupQuery = useQuery({
    queryKey: ['stream-default-group-options', scopeKind, scopeID, sessionEpoch, targetScopeID, targetOwnerID],
    queryFn: async () => {
      const items: StreamGroup[] = []
      for (let groupPage = 1; ; groupPage += 1) {
        if (!canRead(scopeKind, scopeID, sessionEpoch) || !canManage(scopeKind, scopeID, sessionEpoch)) throw staleDefaultRead
        const response = await streamGroupsApi.listGroups(accessTokenRef.current, { page: groupPage, limit: 100 })
        if (!canRead(scopeKind, scopeID, sessionEpoch) || !canManage(scopeKind, scopeID, sessionEpoch)) throw staleDefaultRead
        items.push(...response.items.filter((group) => group.scope_id === targetScopeID && group.owner?.id === targetOwnerID))
        if (groupPage * response.limit >= response.total || response.items.length === 0) return items
      }
    },
    enabled: modalOpen && scopeName === 'group' && Boolean(targetScopeID && targetOwnerID) && canManageDefaults,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  })

  useEffect(() => {
    if (!canManageDefaults) {
      setModalOpen(false)
      setSelectedRowKeys([])
    }
  }, [canManageDefaults])

  const invalidate = () => queryClient.invalidateQueries({
    queryKey: ['stream-user-configs', scopeKind, scopeID, sessionEpoch],
  })

  const forbidden = query.error instanceof ApiError && query.error.status === 403
  const writes = useStreamPanelWrites<CreateStreamUserConfigRequest, StreamUserConfig>({
    sameSession: () => sessionMatches(scopeKind, scopeID, sessionEpoch),
    canWrite: () => canManage(scopeKind, scopeID, sessionEpoch) && canRead(scopeKind, scopeID, sessionEpoch) && !forbidden,
    blocked: lockWrites || query.isFetching,
    recoveryKey: ['stream-default-recovery', scopeKind, scopeID, sessionEpoch],
    create: (input, key) => streamGroupsApi.createUserConfig(accessTokenRef.current, input, key),
    remove: (item, key) => streamGroupsApi.removeUserConfig(accessTokenRef.current, item, key),
    invalidate,
    created: () => { setModalOpen(false); messageApi.success(t('defaults.created')) },
    deleted: (failedIDs) => {
      setSelectedRowKeys(failedIDs)
      if (failedIDs.length === 0) messageApi.success(t('defaults.deleted'))
    },
  })
  const pending = writes.pending
  const writeError = writes.error
  const writesLocked = lockWrites || pending || writes.uncertain || query.isFetching || forbidden
  const ownerUnavailable = isAdmin && (!canReadOwners() || ownerQuery.isError || ownerQuery.isFetching || !ownerQuery.data)
  const groupUnavailable = scopeName === 'group' && (!targetScopeID || !targetOwnerID || groupQuery.isFetching || groupQuery.isError || !groupQuery.data)

  useEffect(() => { if (writes.uncertain) setModalOpen(false) }, [writes.uncertain])
  useEffect(() => () => {
    if (!canRead(scopeKind, scopeID, sessionEpoch)) {
      queryClient.removeQueries({ queryKey: ['stream-user-configs', scopeKind, scopeID, sessionEpoch] })
      queryClient.removeQueries({ queryKey: ['stream-panel-owner-options', scopeKind, scopeID, sessionEpoch] })
      queryClient.removeQueries({ queryKey: ['stream-default-group-options', scopeKind, scopeID, sessionEpoch] })
    }
  }, [queryClient, scopeKind, scopeID, sessionEpoch])
  useEffect(() => {
    if (query.data && !query.isFetching && page > 1 && query.data.total <= (page - 1) * limit) {
      setPage(Math.max(1, Math.ceil(query.data.total / limit)))
    }
  }, [query.data, query.isFetching, page, limit])

  const selectedConfigs = (query.data?.items ?? []).filter((item) => selectedRowKeys.includes(item.id))

  const beginDelete = (items: StreamUserConfig[]) => {
    if (items.length === 0) return
    modalApi.confirm({
      title: t('defaults.deleteTitle'),
      content: t('defaults.deleteDescription'),
      okText: t('actions.confirmDelete'),
      okButtonProps: { danger: true },
      cancelText: t('actions.cancel'),
      onOk: () => {
        if (!canManage(scopeKind, scopeID, sessionEpoch)) return
        writes.remove(items)
      },
    })
  }

  const columns: TableColumnsType<StreamUserConfig> = [
    {
      title: t('columns.id'), dataIndex: 'display_id', width: 78,
      render: (_: string, item) => <ResourceID internalId={item.id} displayId={item.display_id} />,
    },
    {
      title: t('defaults.user'), key: 'owner', width: 180,
      render: (_, item) => <span className={item.owner ? undefined : 'stream-unavailable'}>
        {item.owner?.display_name ?? t('values.unavailable')}
      </span>,
    },
    {
      title: t('defaults.settingName'), key: 'settingName', width: 160,
      render: (_, item) => settingNameOptions.find((option) => option.value === item.setting_name)?.label ?? item.setting_name,
    },
    {
      title: t('defaults.settingValue'), key: 'settingValue', width: 140,
      render: (_, item) => settingValueLabel(item.setting_name, item.setting_value),
    },
    {
      title: t('defaults.scope'), key: 'scope', width: 180,
      render: (_, item) => item.scope_name === 'group'
        ? <span>{t('defaults.scopeGroup')}{item.group ? ` ${item.group.name}` : ''}</span>
        : <span>{t('defaults.scopeGlobal')}</span>,
    },
    {
      title: t('columns.actions'), key: 'actions', width: 118, fixed: 'right',
      render: (_, item) => <Button
        type="link"
        size="small"
        danger
        disabled={!canManageDefaults || writesLocked}
        onClick={() => beginDelete([item])}
      >
        {t('defaults.delete')}
      </Button>,
    },
  ]

  const submit = (values: DefaultFormValues) => {
    if (!canManageDefaults || writesLocked || ownerUnavailable || groupUnavailable || !canManage(scopeKind, scopeID, sessionEpoch)) return
    const owner = isAdmin ? ownerQuery.data?.find((user) => user.id === values.owner_id) : undefined
    if (isAdmin && !owner) return
    if (values.scope_name === 'group' && !groupQuery.data?.some((group) => group.id === values.group_id)) return
    writes.create({
      setting_name: values.setting_name,
      setting_value: values.setting_value,
      scope_name: values.scope_name,
      ...(values.scope_name === 'group' ? { group_id: values.group_id?.trim() } : {}),
      ...(owner ? { owner_id: owner.id, target_scope_id: owner.scope_id } : {}),
    })
  }

  return (
    <>
      {messageContext}
      {modalContext}
      <p className="stream-panel-description">{t('defaults.description')}</p>
      <div className="stream-panel-toolbar stream-defaults-toolbar is-end">
        <div className="stream-toolbar-actions">
          {canManageDefaults ? <Button type="primary" icon={<Plus size={15} />} disabled={writesLocked} onClick={() => {
            writes.clearError()
            form.resetFields()
            form.setFieldsValue({ setting_name: 'listen_protocol', setting_value: 'tcp', scope_name: 'global' })
            setModalOpen(true)
          }}>{t('defaults.add')}</Button> : null}
          {canManageDefaults ? <Button disabled={writesLocked || selectedConfigs.length === 0} onClick={() => beginDelete(selectedConfigs)}>{t('defaults.delete')}</Button> : null}
        </div>
      </div>

      {writes.uncertain ? <OutcomeUnknown className="identity-alert" title={tp('unknown')} detail={tp('unknownDescription')} action={canManageDefaults ? <Button size="small" loading={pending} disabled={pending || lockWrites || query.isFetching || forbidden} onClick={writes.retry}>{tp('retryExact')}</Button> : undefined} /> : writeError ? <FeedbackWhen title={t('defaults.writeFailed')} detail={defaultErrorMessage(writeError, t)} onClose={writes.clearError} /> : null}
      {query.isError ? <FeedbackWhen title={t('defaults.listFailed')} detail={query.error instanceof ApiError ? defaultErrorMessage(query.error, t) : t('errors.requestFailed')} action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} /> : null}
      <div className="identity-table-scroll" data-testid="stream-default-table-scroll" aria-busy={query.isPending || query.isFetching}>
        <Table<StreamUserConfig>
          rowKey="id"
          size="small"
          rowSelection={canManageDefaults ? { selectedRowKeys, onChange: (keys) => setSelectedRowKeys(keys.map(String)) } : undefined}
          columns={columns}
          dataSource={forbidden ? [] : query.data?.items ?? []}
          loading={query.isPending || query.isFetching}
          pagination={false}
          scroll={{ x: 900 }}
          locale={{ emptyText: query.isPending ? ' ' : t('values.empty') }}
        />
      </div>
      <Pagination className="identity-pagination" current={page} pageSize={limit} total={query.data?.total ?? 0} pageSizeOptions={[10, 20, 50, 100]} showSizeChanger showTotal={(count) => t('values.total', { count })} onChange={(nextPage, nextLimit) => { setPage(nextLimit === limit ? nextPage : 1); setLimit(nextLimit) }} />

      <Modal
        className="identity-modal stream-modal"
        title={t('defaults.addTitle')}
        open={canManageDefaults && modalOpen}
        onCancel={() => { if (writesLocked) return; setModalOpen(false) }}
        onOk={() => form.submit()}
        confirmLoading={pending}
        okText={t('actions.confirm')}
        cancelText={t('actions.cancel')}
        okButtonProps={{ disabled: writesLocked || ownerUnavailable || groupUnavailable }}
        destroyOnHidden
        /* 该弹窗的按钮顺序与分组弹窗相反：确定在左、取消在右。 */
        footer={[
          <Button key="ok" type="primary" loading={pending} disabled={writesLocked || ownerUnavailable || groupUnavailable} onClick={() => form.submit()}>{t('actions.confirm')}</Button>,
          <Button key="cancel" disabled={pending} onClick={() => { if (writesLocked) return; setModalOpen(false) }}>{t('actions.cancel')}</Button>,
        ]}
      >
        {isAdmin && (!canReadOwners() || ownerQuery.isError) ? <Alert className="identity-alert" type="error" showIcon message={tp(canReadOwners() ? 'ownersFailed' : 'ownersForbidden')} action={canReadOwners() ? <Button size="small" onClick={() => void ownerQuery.refetch()}>{t('actions.retry')}</Button> : undefined} /> : null}
        {scopeName === 'group' && groupQuery.isError ? <Alert className="identity-alert" type="error" showIcon message={t('groups.listFailed')} action={<Button size="small" onClick={() => void groupQuery.refetch()}>{t('actions.retry')}</Button>} /> : null}
        <Form form={form} disabled={pending} layout="horizontal" labelCol={{ flex: '88px' }} wrapperCol={{ flex: 1 }} requiredMark={false} onFinish={submit}>
          <Form.Item name="owner_id" label={t('defaults.user')} rules={isAdmin ? [
            { required: true, message: t('groups.userRequired') },
            { pattern: uuidPattern, message: t('groups.userInvalid') },
          ] : []}>
            {isAdmin ? <Select
              showSearch
              optionFilterProp="label"
              placeholder={t('defaults.user')}
              loading={ownerQuery.isFetching}
              disabled={ownerUnavailable}
              onChange={() => form.setFieldValue('group_id', undefined)}
              options={(ownerQuery.data ?? []).map((user) => ({ value: user.id, label: user.display_name || user.username }))}
            /> : <Input disabled placeholder={t('defaults.user')} />}
          </Form.Item>
          <Form.Item name="setting_name" label={t('defaults.settingName')} rules={[{ required: true, message: t('defaults.settingRequired') }]}>
            <Select
              options={settingNameOptions}
              onChange={(value: StreamSettingName) => form.setFieldValue('setting_value', SETTING_VALUES[value][0])}
            />
          </Form.Item>
          <Form.Item name="setting_value" label={t('defaults.settingValue')} rules={[{ required: true, message: t('defaults.settingRequired') }]}>
            <Select
              options={(SETTING_VALUES[settingName ?? 'listen_protocol']).map((value) => ({
                value,
                label: settingValueLabel(settingName ?? 'listen_protocol', value),
              }))}
            />
          </Form.Item>
          <Form.Item name="scope_name" label={t('defaults.scope')} rules={[{ required: true, message: t('defaults.scopeRequired') }]}>
            <Radio.Group buttonStyle="solid" onChange={() => form.setFieldValue('group_id', undefined)}>
              <Radio.Button value="global">{t('defaults.scopeGlobal')}</Radio.Button>
              <Radio.Button value="group">{t('defaults.scopeGroup')}</Radio.Button>
            </Radio.Group>
          </Form.Item>
          {scopeName === 'group' ? <Form.Item name="group_id" label={t('defaults.group')} rules={[
            { required: true, message: t('defaults.groupRequired') },
          ]}>
            <Select
              showSearch
              optionFilterProp="label"
              placeholder={t('defaults.group')}
              loading={groupQuery.isFetching}
              disabled={groupUnavailable}
              options={(groupQuery.data ?? []).map((group) => ({ value: group.id, label: group.name }))}
            />
          </Form.Item> : null}
        </Form>
      </Modal>
    </>
  )
}
