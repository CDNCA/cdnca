import { useCallback, useEffect, useMemo, useRef, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Form, Input, InputNumber, Modal, Result, Select, Table, Tooltip, type TableColumnsType } from 'antd'
import { useFeedbackMessage, FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'
import { ChevronLeft, ChevronRight, Plus, Search, Trash2 } from 'lucide-react'
import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import { regionsApi, type RegionInput, type RegionRecord } from '../api/nodes'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import { localizedUnknownApiError } from '../i18n/apiError'
import { countryOptions, geoLabel, provinceOptions } from './regionGeo'
import './NodeListPage.locale'

interface RegionFormValues {
  name: string
  country_code?: string
  province_code?: string
  description: string
  l2_check_port: number
  sort: number
}

type RegionWriteAttempt =
  | { kind: 'create'; input: RegionInput; key: string; ownerKey: string }
  | { kind: 'update'; item: Pick<RegionRecord, 'id' | 'revision'>; input: RegionInput; key: string; ownerKey: string }
  | { kind: 'delete'; items: Array<{ item: Pick<RegionRecord, 'id' | 'revision'>; key: string }>; ownerKey: string }

const staleRegionRead = new Error('Region catalog session owner changed during read')
const staleRegionWrite = new Error('Region catalog session owner changed during write')
const pageSizes = [10, 30, 100, 300] as const

function regionOwner(principal: Principal, sessionEpoch: number): string | null {
  if (principal.scope_kind !== 'platform' || principal.tenant_id !== null || !principal.scope_id ||
    !principal.user_id || sessionEpoch <= 0) return null
  return JSON.stringify(['platform', principal.scope_id, null, principal.user_id, sessionEpoch])
}

function hasPermission(principal: Principal, permission: 'regions.read' | 'regions.manage'): boolean {
  return principal.permissions.includes('platform.admin') || principal.permissions.includes(permission)
}

function currentRegionAccess(ownerKey: string, permission: 'read' | 'manage'): string | null {
  const { accessToken, principal, sessionEpoch } = useSessionStore.getState()
  if (!accessToken || !principal || regionOwner(principal, sessionEpoch) !== ownerKey ||
    !hasPermission(principal, permission === 'read' ? 'regions.read' : 'regions.manage')) return null
  return accessToken
}

function writeKey(operation: string): string {
  const suffix = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`
  return `${operation}-${suffix}`
}

function writeOutcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

function regionErrorCodeMessage(code: string, t: TFunction<'nodes'>): string {
  switch (code) {
    case 'regions_validation_error':
    case 'regions_not_found':
    case 'regions_name_conflict':
    case 'regions_idempotency_conflict':
    case 'regions_in_use':
    case 'regions_revision_conflict':
    case 'regions_precondition_required':
    case 'regions_unavailable':
      return t(`regions.errors.${code}`)
    default:
      return t('regions.errors.requestFailed')
  }
}

function regionErrorMessage(error: ApiError, t: TFunction<'nodes'>): string {
  return localizedUnknownApiError(error, regionErrorCodeMessage(error.code, t))
}

function RegionEditorModal({
  item,
  open,
  pending,
  error,
  onCancel,
  onSubmit,
}: {
  item: RegionRecord | null
  open: boolean
  pending: boolean
  error: ApiError | null
  onCancel: () => void
  onSubmit: (values: RegionFormValues) => void
}) {
  const { t, i18n } = useTranslation('nodes')
  const [form] = Form.useForm<RegionFormValues>()
  const locale = i18n.resolvedLanguage ?? i18n.language
  const countries = useMemo(() => countryOptions(locale), [locale])
  const provinces = useMemo(() => provinceOptions(locale), [locale])
  const country = Form.useWatch('country_code', form)

  useEffect(() => {
    if (!open) return
    form.resetFields()
    form.setFieldsValue({
      name: item?.name ?? '',
      country_code: item?.country_code || undefined,
      province_code: item?.province_code || undefined,
      description: item?.description ?? '',
      l2_check_port: item?.l2_check_port ?? 80,
      sort: item?.sort ?? 100,
    })
  }, [form, item, open])

  return (
    <Modal
      className="node-modal node-region-modal"
      title={item ? t('regions.editTitle') : t('regions.addTitle')}
      open={open}
      width={520}
      closable={!pending}
      maskClosable={!pending}
      keyboard={!pending}
      footer={[
        <Button key="cancel" disabled={pending} onClick={onCancel}>{t('actions.cancel')}</Button>,
        <Button key="confirm" type="primary" loading={pending} onClick={() => form.submit()}>{t('regions.confirm')}</Button>,
      ]}
      onCancel={onCancel}
      destroyOnHidden
    >
      {error ? <Alert className="node-region-modal-alert" type="error" showIcon message={regionErrorMessage(error, t)} /> : null}
      <Form
        className="node-region-form"
        form={form}
        labelCol={{ flex: '104px' }}
        wrapperCol={{ flex: 'auto' }}
        requiredMark={false}
        onFinish={onSubmit}
      >
        <Form.Item name="name" label={t('regions.name')} rules={[{ required: true, whitespace: true, max: 128 }]}>
          <Input autoFocus placeholder={t('regions.namePlaceholder')} />
        </Form.Item>
        <Form.Item name="country_code" label={t('regions.country')} extra={t('regions.countryHelp')}>
          <Select
            aria-label={t('regions.country')}
            allowClear
            showSearch
            optionFilterProp="label"
            placeholder={t('regions.countryPlaceholder')}
            options={countries}
            onChange={(value?: string) => { if (value !== 'CN') form.setFieldValue('province_code', undefined) }}
          />
        </Form.Item>
        <Form.Item name="province_code" label={t('regions.province')}>
          <Select
            aria-label={t('regions.province')}
            allowClear
            showSearch
            optionFilterProp="label"
            disabled={country !== 'CN'}
            placeholder={t('regions.provincePlaceholder')}
            options={provinces}
          />
        </Form.Item>
        <Form.Item name="description" label={t('regions.description')} rules={[{ max: 1024 }]}>
          <Input placeholder={t('regions.descriptionPlaceholder')} />
        </Form.Item>
        <Form.Item
          name="l2_check_port"
          label={t('regions.l2CheckPort')}
          extra={t('regions.l2CheckPortHelp')}
          rules={[{ required: true, type: 'number', min: 1, max: 65535 }]}
        >
          <InputNumber min={1} max={65535} precision={0} />
        </Form.Item>
        <Form.Item name="sort" label={t('regions.sort')} rules={[{ required: true, type: 'number', min: 0, max: 999999 }]}>
          <InputNumber min={0} max={999999} precision={0} />
        </Form.Item>
        <p className="node-region-warning">
          {t('regions.warningLine1')}<br />
          {t('regions.warningLine2')}
        </p>
      </Form>
    </Modal>
  )
}

export default function RegionManagementPanel() {
  const { t, i18n } = useTranslation('nodes')
  const principal = useSessionStore((state) => state.principal)
  const accessToken = useSessionStore((state) => state.accessToken)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const [confirm, confirmContext] = Modal.useModal()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [searchDraft, setSearchDraft] = useState('')
  const [search, setSearch] = useState('')
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([])
  const [editing, setEditing] = useState<RegionRecord | null>(null)
  const [editorOpen, setEditorOpen] = useState(false)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [retryAttempt, setRetryAttempt] = useState<RegionWriteAttempt | null>(null)
  const [terminalForbidden, setTerminalForbidden] = useState(false)
  const lineageActiveRef = useRef(true)

  const ownerKey = principal ? regionOwner(principal, sessionEpoch) : null
  const canRead = Boolean(accessToken && principal && ownerKey && hasPermission(principal, 'regions.read'))
  const canManage = Boolean(accessToken && principal && ownerKey && hasPermission(principal, 'regions.manage'))
  const queryPrefix = useMemo(() => ['regions', ownerKey ?? 'invalid'] as const, [ownerKey])
  const mutationPrefix = useMemo(() => ['regions-write', ownerKey ?? 'invalid'] as const, [ownerKey])
  const queryKey = useMemo(() => [...queryPrefix, page, pageSize, search] as const, [page, pageSize, queryPrefix, search])
  const queryIdentity = JSON.stringify(queryKey)
  const activeQueryIdentityRef = useRef(queryIdentity)
  activeQueryIdentityRef.current = queryIdentity
  const currentAccess = useCallback((permission: 'read' | 'manage') => (
    lineageActiveRef.current && ownerKey ? currentRegionAccess(ownerKey, permission) : null
  ), [ownerKey])

  const removeOwnerCache = useCallback(() => {
    queryClient.removeQueries({ queryKey: queryPrefix })
    const mutationCache = queryClient.getMutationCache()
    for (const mutation of mutationCache.findAll({ mutationKey: mutationPrefix })) mutationCache.remove(mutation)
  }, [mutationPrefix, queryClient, queryPrefix])

  useEffect(() => {
    lineageActiveRef.current = true
    return () => {
      lineageActiveRef.current = false
      if (!ownerKey || !currentRegionAccess(ownerKey, 'read')) {
        removeOwnerCache()
        return
      }
      queueMicrotask(() => {
        if (!lineageActiveRef.current) removeOwnerCache()
      })
    }
  }, [ownerKey, removeOwnerCache])

  const listQuery = useQuery({
    queryKey,
    queryFn: async () => {
      const token = currentAccess('read')
      if (!token) throw staleRegionRead
      try {
        const result = await regionsApi.list(token, { page, page_size: pageSize, search })
        if (!currentAccess('read') || activeQueryIdentityRef.current !== queryIdentity) throw staleRegionRead
        return result
      } catch (error) {
        if (!currentAccess('read') || activeQueryIdentityRef.current !== queryIdentity) throw staleRegionRead
        throw error
      }
    },
    enabled: canRead && !terminalForbidden,
    retry: false,
    refetchOnReconnect: false,
    refetchOnWindowFocus: false,
  })

  const denyCurrentRegion = useCallback(() => {
    lineageActiveRef.current = false
    setTerminalForbidden(true)
    setEditing(null)
    setEditorOpen(false)
    setSelectedKeys([])
    setWriteError(null)
    setRetryAttempt(null)
    queueMicrotask(removeOwnerCache)
  }, [removeOwnerCache])

  useEffect(() => {
    if (listQuery.error instanceof ApiError && listQuery.error.status === 403 && currentAccess('read')) denyCurrentRegion()
  }, [currentAccess, denyCurrentRegion, listQuery.error])

  useEffect(() => setSelectedKeys([]), [listQuery.data, page, pageSize, search])

  const writeMutation = useMutation<RegionRecord | null, unknown, RegionWriteAttempt>({
    mutationKey: [...mutationPrefix, 'write'],
    mutationFn: async (attempt) => {
      const token = attempt.ownerKey === ownerKey ? currentAccess('manage') : null
      if (!token) throw staleRegionWrite
      try {
        let result: RegionRecord | null
        if (attempt.kind === 'create') result = await regionsApi.create(token, attempt.input, attempt.key)
        else if (attempt.kind === 'update') result = await regionsApi.update(token, attempt.item, attempt.input, attempt.key)
        else {
          for (const entry of attempt.items) {
            await regionsApi.delete(token, entry.item, entry.key)
            if (!currentAccess('manage')) throw staleRegionWrite
          }
          result = null
        }
        if (!currentAccess('manage')) throw staleRegionWrite
        return result
      } catch (error) {
        if (!currentAccess('manage')) throw staleRegionWrite
        throw error
      }
    },
    onSuccess: async (_, attempt) => {
      if (attempt.ownerKey !== ownerKey || !currentAccess('manage')) return
      setRetryAttempt(null)
      setWriteError(null)
      setEditing(null)
      setEditorOpen(false)
      setSelectedKeys([])
      if (attempt.kind === 'delete' && page > 1 && attempt.items.length >= (listQuery.data?.data.length ?? 0)) setPage((value) => value - 1)
      await queryClient.invalidateQueries({ queryKey: queryPrefix })
      if (!currentAccess('manage')) return
      const notice = attempt.kind === 'create' ? 'created' : attempt.kind === 'update' ? 'updated' : 'deleted'
      messageApi.success(t(`regions.notices.${notice}`))
    },
    onError: (error, attempt) => {
      if (error === staleRegionWrite || attempt.ownerKey !== ownerKey || !currentAccess('manage')) return
      const apiError = error instanceof ApiError ? error : new ApiError(t('regions.errors.requestFailed'))
      if (apiError.status === 403) {
        denyCurrentRegion()
        return
      }
      const unknown = writeOutcomeUnknown(error)
      setRetryAttempt(unknown ? attempt : null)
      setWriteError(apiError)
      if (unknown || apiError.status === 412) {
        setEditing(null)
        setEditorOpen(false)
      }
      if (apiError.status === 412) void queryClient.invalidateQueries({ queryKey: queryPrefix })
    },
  })

  if (!canRead || terminalForbidden) {
    return (
      <div className="node-region-panel">
        {messageContext}
        {confirmContext}
        <Result status="403" title={t('regions.errors.forbiddenTitle')} subTitle={t('regions.errors.forbiddenDescription')} />
      </div>
    )
  }

  const rows = listQuery.data?.data ?? []
  const selected = rows.filter((item) => new Set(selectedKeys.map(String)).has(item.id))
  const writeLocked = retryAttempt !== null
  const queryError = listQuery.error instanceof ApiError ? listQuery.error : null
  const pageCount = Math.max(1, Math.ceil((listQuery.data?.count ?? 0) / pageSize))

  const submit = (values: RegionFormValues) => {
    const token = currentAccess('manage')
    if (!token || !ownerKey || !canManage || writeLocked) return
    const input: RegionInput = {
      name: values.name.trim(),
      country_code: values.country_code ?? '',
      province_code: values.country_code === 'CN' ? values.province_code ?? '' : '',
      description: values.description.trim(),
      l2_check_port: values.l2_check_port,
      sort: values.sort,
    }
    setWriteError(null)
    if (editing) {
      writeMutation.mutate({
        kind: 'update', item: { id: editing.id, revision: editing.revision }, input,
        key: writeKey(`update-region-${editing.id}`), ownerKey,
      })
    } else {
      writeMutation.mutate({ kind: 'create', input, key: writeKey('create-region'), ownerKey })
    }
  }

  const deleteRegions = (items: RegionRecord[]) => {
    if (!ownerKey || !canManage || writeLocked || items.length === 0 || !currentAccess('manage')) return
    confirm.confirm({
      title: items.length === 1
        ? t('regions.deleteConfirm', { id: items[0]!.id })
        : t('regions.batchDeleteConfirm', { count: items.length }),
      okText: t('regions.confirm'),
      cancelText: t('actions.cancel'),
      okButtonProps: { danger: true },
      onOk: () => {
        if (!ownerKey || !currentAccess('manage') || retryAttempt) return
        setWriteError(null)
        writeMutation.mutate({
          kind: 'delete',
          ownerKey,
          items: items.map((item) => ({
            item: { id: item.id, revision: item.revision },
            key: writeKey(`delete-region-${item.id}`),
          })),
        })
      },
    })
  }

  const columns: TableColumnsType<RegionRecord> = [
    { title: t('columns.id'), dataIndex: 'id', width: 64 },
    { title: t('regions.name'), dataIndex: 'name', width: 160, ellipsis: true },
    { title: <span title={t('regions.codeHelp')}>{t('regions.code')}</span>, dataIndex: 'code', width: 120 },
    {
      title: t('regions.geo'), key: 'geo', width: 150, ellipsis: true,
      render: (_, item) => geoLabel(item.country_code, item.province_code, i18n.resolvedLanguage ?? i18n.language) ||
        <span className="node-region-geo-unset">{t('regions.geoUnset')}</span>,
    },
    { title: t('regions.description'), dataIndex: 'description', ellipsis: true, render: (value: string) => value || '—' },
    { title: t('regions.sort'), dataIndex: 'sort', width: 80 },
    {
      title: t('columns.createdAt'), dataIndex: 'created_at', width: 175,
      render: (value: string) => formatDateTime(value, i18n.resolvedLanguage ?? i18n.language) || value,
    },
    {
      title: t('columns.actions'), key: 'actions', width: 120, align: 'center',
      render: (_, item) => canManage ? (
        <div className="node-region-row-actions">
          <Button type="link" size="small" disabled={writeLocked || writeMutation.isPending} onClick={() => {
            setWriteError(null)
            setEditing(item)
            setEditorOpen(true)
          }}>{t('actions.edit')}</Button>
          <Button type="link" size="small" danger disabled={writeLocked || writeMutation.isPending} onClick={() => deleteRegions([item])}>
            {t('actions.delete')}
          </Button>
        </div>
      ) : '—',
    },
  ]

  return (
    <div className="node-region-panel">
      {messageContext}
      {confirmContext}
      <div className="node-toolbar node-region-toolbar">
        <div className="node-toolbar-actions">
          {canManage ? (
            <>
              <Button type="primary" icon={<Plus size={14} />} disabled={writeLocked || writeMutation.isPending} onClick={() => {
                setWriteError(null)
                setEditing(null)
                setEditorOpen(true)
              }}>{t('regions.add')}</Button>
              <Button
                type="primary"
                danger
                icon={<Trash2 size={14} />}
                disabled={writeLocked || writeMutation.isPending || selected.length === 0}
                onClick={() => deleteRegions(selected)}
              >{t('actions.delete')}</Button>
            </>
          ) : null}
        </div>
        <div className="node-region-search">
          <Input
            aria-label={t('regions.searchLabel')}
            value={searchDraft}
            placeholder={t('regions.searchPlaceholder')}
            suffix={(
              <button className="node-search-icon-button" type="button" aria-label={t('actions.search')} onClick={() => {
                setPage(1)
                setSearch(searchDraft.trim())
              }}>
                <Search size={14} aria-hidden="true" />
              </button>
            )}
            onChange={(event) => setSearchDraft(event.target.value)}
            onPressEnter={() => { setPage(1); setSearch(searchDraft.trim()) }}
          />
        </div>
      </div>

      {writeError && !editorOpen ? (
        (retryAttempt ? <OutcomeUnknown title={t('regions.errors.outcomeUnknown')} detail={t('regions.errors.retryDescription')} action={(
            <Button size="small" loading={writeMutation.isPending} onClick={() => {
              if (retryAttempt.ownerKey === ownerKey && currentAccess('manage')) writeMutation.mutate(retryAttempt)
            }}>{t('actions.retrySameRequest')}</Button>
          )} className="node-alert" /> : <FeedbackWhen title={regionErrorMessage(writeError, t)} onClose={() => setWriteError(null)} />)
      ) : null}

      {listQuery.isError ? (
        <FeedbackWhen title={t('regions.errors.listFailed')} detail={queryError ? regionErrorMessage(queryError, t) : t('regions.errors.requestFailed')} action={<Button size="small" onClick={() => void listQuery.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}

      <div className="node-table-scroll node-table-scroll--regions" aria-busy={listQuery.isPending || listQuery.isFetching}>
        <Table<RegionRecord>
          rowKey="id"
          size="small"
          columns={columns}
          dataSource={rows}
          loading={listQuery.isPending || listQuery.isFetching}
          pagination={false}
          locale={{ emptyText: listQuery.isPending ? ' ' : search ? t('regions.filteredEmpty') : t('regions.empty') }}
          scroll={{ x: 910 }}
          rowSelection={canManage ? {
            selectedRowKeys: selectedKeys,
            onChange: setSelectedKeys,
            getCheckboxProps: (item) => ({ disabled: writeLocked || writeMutation.isPending, 'aria-label': item.name }),
          } : undefined}
        />
      </div>
      <div className="node-pagination">
        <span className="node-total">{t('pagination.total', { count: listQuery.data?.count ?? 0 })}</span>
        <Tooltip title={t('actions.previousPage')}>
          <Button aria-label={t('actions.previousPage')} icon={<ChevronLeft size={16} />} disabled={page <= 1 || listQuery.isFetching} onClick={() => setPage((value) => Math.max(1, value - 1))} />
        </Tooltip>
        <span className="node-page-number" aria-current="page">{page}</span>
        <Tooltip title={t('actions.nextPage')}>
          <Button aria-label={t('actions.nextPage')} icon={<ChevronRight size={16} />} disabled={page >= pageCount || listQuery.isFetching} onClick={() => setPage((value) => Math.min(pageCount, value + 1))} />
        </Tooltip>
        <Select
          classNames={{ popup: { root: 'node-select-popup node-page-size-popup' } }}
          aria-label={t('filters.pageSizeLabel')}
          placement="bottomLeft"
          virtual={false}
          listHeight={200}
          popupMatchSelectWidth
          value={pageSize}
          options={pageSizes.map((value) => ({ value, label: t('filters.pageSize', { count: value }) }))}
          onChange={(value) => { setPageSize(value); setPage(1) }}
        />
      </div>

      <RegionEditorModal
        item={editing}
        open={editorOpen}
        pending={writeMutation.isPending}
        error={editorOpen ? writeError : null}
        onCancel={() => {
          if (writeMutation.isPending) return
          setEditing(null)
          setEditorOpen(false)
          setWriteError(null)
        }}
        onSubmit={submit}
      />
    </div>
  )
}
