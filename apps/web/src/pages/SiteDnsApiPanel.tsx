import { useRef, useState } from 'react'
import { Button, Pagination, Popconfirm, Space, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { CircleCheck, Pencil, Plus, Trash2 } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FeedbackWhen } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { dnsApi, type CreateDNSProviderInput, type DNSProvider, type UpdateDNSProviderInput } from '../api/dns'
import { useSessionStore } from '../auth/session'
import {
  credentialFields, errorMessage, isCreatableProviderType, ProviderEditor, providerLabel,
  type DNSProviderEditorState, type ProviderForm,
} from './NodeDnsPage'

// 网站管理 > DNS API（用户端）：本租户自己的 DNS 服务商账号，
// 走租户级 /v1/dns/providers（按 scope 隔离，dns.read / dns.manage），
// 供 DNS-01 证书验证与租户 DNS 区域使用。管理员的平台 DNS 配置在 /node/dns，用户端不跳转过去。
type Write =
  | { kind: 'create'; input: CreateDNSProviderInput }
  | { kind: 'update'; id: string; providerType: string; input: UpdateDNSProviderInput }
  | { kind: 'verify'; id: string; providerType: string; version: number }
  | { kind: 'delete'; id: string; version: number }
type Attempt = Write & { key: string }

function attemptKey(kind: Write['kind']): string {
  return `site-dns-api-${kind}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`
}

// 网络中断/超时/5xx 时结果未知，保留同一幂等键供重试。
function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

// 平台 DNS 配置同步来的副本：平台只用它维护网站 CNAME，用户不能编辑、删除、验证或拿去做本人用途
// （DNS-SEC-20261027-01，服务端同样拒绝）。
function platformManaged(item: DNSProvider): boolean {
  return item.managed_by === 'platform'
}

function clearCredentials(attempt: Attempt | null): void {
  const credentials = attempt?.kind === 'create' || attempt?.kind === 'update' ? attempt.input.credentials : undefined
  if (credentials) for (const key of Object.keys(credentials)) credentials[key] = ''
}

export default function SiteDnsApiPanel() {
  const { t } = useTranslation('dnsProviders')
  const { t: certT } = useTranslation('certificates')
  const queryClient = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canManage = Boolean(principal?.permissions.includes('dns.manage'))
  const queryKey = ['site-dns-api', principal?.scope_id, principal?.user_id, sessionEpoch]
  const [editor, setEditor] = useState<DNSProviderEditorState | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const attemptRef = useRef<Attempt | null>(null)
  const [attempt, setAttempt] = useState<Attempt | null>(null)

  const token = (permission: string) => {
    const state = useSessionStore.getState()
    return state.accessToken && state.principal?.permissions.includes(permission) ? state.accessToken : null
  }

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const accessToken = token('dns.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      return dnsApi.list(accessToken)
    },
  })

  const mutation = useMutation<void, unknown, void>({
    mutationFn: async () => {
      const frozen = attemptRef.current
      const accessToken = token('dns.manage')
      if (!frozen || !accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      if (frozen.kind === 'create') await dnsApi.create(accessToken, frozen.input, frozen.key)
      else if (frozen.kind === 'update') await dnsApi.update(accessToken, frozen.id, frozen.providerType, frozen.input, frozen.key)
      else if (frozen.kind === 'verify') await dnsApi.verify(accessToken, frozen.id, frozen.providerType, frozen.version, frozen.key)
      else await dnsApi.remove(accessToken, frozen.id, frozen.version, frozen.key)
    },
    onSuccess: async () => {
      clearCredentials(attemptRef.current)
      attemptRef.current = null
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      await queryClient.invalidateQueries({ queryKey })
    },
    onError: (error) => {
      setWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
      if (!outcomeUnknown(error)) {
        clearCredentials(attemptRef.current)
        attemptRef.current = null
        setAttempt(null)
      }
    },
  })

  const start = (next: Write) => {
    if (!token('dns.manage')) return
    clearCredentials(attemptRef.current)
    const value = { ...next, key: attemptKey(next.kind) } as Attempt
    attemptRef.current = value
    setAttempt(value)
    setWriteError(null)
    mutation.mutate()
  }

  const submit = (values: ProviderForm) => {
    if (!editor) return
    if (editor.mode === 'create') {
      if (!isCreatableProviderType(values.provider_type)) return
      const credentials = Object.fromEntries(credentialFields[values.provider_type].map((field) => [field.name, values.credentials[field.name]]))
      start({ kind: 'create', input: { name: values.name.trim(), remark: (values.remark ?? '').trim(), provider_type: values.provider_type, credentials } })
      return
    }
    const item = editor.item
    const type = item.provider_type
    start({
      kind: 'update', id: item.id, providerType: type,
      input: {
        expected_version: item.version, name: values.name.trim(), remark: (values.remark ?? '').trim(), status: isCreatableProviderType(type) ? values.status : 'disabled',
        ...(isCreatableProviderType(type) && values.replace_credentials ? {
          credentials: Object.fromEntries(credentialFields[type].map((field) => [field.name, values.credentials[field.name]])),
        } : {}),
      },
    })
  }

  const closeAndRefresh = () => {
    clearCredentials(attemptRef.current)
    attemptRef.current = null
    setAttempt(null)
    setWriteError(null)
    setEditor(null)
    void query.refetch()
  }

  const deleteSelected = async () => {
    const accessToken = token('dns.manage')
    if (!accessToken) return
    try {
      for (const item of items.filter((value) => selected.includes(value.id) && !platformManaged(value))) {
        await dnsApi.remove(accessToken, item.id, item.version, attemptKey('delete'))
      }
      setSelected([])
    } catch (error) {
      setWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
    }
    await queryClient.invalidateQueries({ queryKey })
  }

  const items = query.data?.items ?? []
  const pageItems = items.slice((page - 1) * limit, page * limit)
  const locked = mutation.isPending || attempt !== null
  const uncertain = attempt !== null && writeError !== null && outcomeUnknown(writeError)
  const columns: TableColumnsType<DNSProvider> = [
    { title: 'ID', dataIndex: 'id', width: 300, ellipsis: true },
    {
      title: t('columns.name'), dataIndex: 'name', ellipsis: true,
      render: (value: string, item) => platformManaged(item) ? (
        <Space size={6}>
          <span>{value}</span>
          <Tooltip title={t('platformManaged.hint')}><Tag>{t('platformManaged.tag')}</Tag></Tooltip>
        </Space>
      ) : value,
    },
    { title: t('columns.provider'), dataIndex: 'provider_type', width: 200, render: (value: string) => providerLabel(value, t) },
    { title: t('columns.remark'), dataIndex: 'remark', ellipsis: true, render: (value?: string) => value || '-' },
    { title: t('columns.status'), dataIndex: 'status', width: 120, render: (value: string) => t(`states.${value}`) },
    {
      title: t('columns.actions'), key: 'actions', width: 140, fixed: 'right',
      render: (_, item) => canManage && !platformManaged(item) ? (
        <Space size={2}>
          {isCreatableProviderType(item.provider_type) ? (
            <Tooltip title={t('actions.verify')}>
              <Button type="text" size="small" aria-label={t('actions.verifyNamed', { name: item.name })} icon={<CircleCheck size={15} />}
                disabled={locked || item.status === 'disabled'}
                onClick={() => start({ kind: 'verify', id: item.id, providerType: item.provider_type, version: item.version })} />
            </Tooltip>
          ) : null}
          <Tooltip title={t('actions.edit')}>
            <Button type="text" size="small" aria-label={t('actions.editNamed', { name: item.name })} icon={<Pencil size={15} />}
              disabled={locked} onClick={() => { setWriteError(null); setEditor({ mode: 'edit', item }) }} />
          </Tooltip>
          <Popconfirm title={t('confirm.delete')} okText={t('actions.delete')} cancelText={t('actions.cancel')} okButtonProps={{ danger: true }}
            onConfirm={() => start({ kind: 'delete', id: item.id, version: item.version })}>
            <Tooltip title={t('actions.delete')}>
              <Button danger type="text" size="small" aria-label={t('actions.deleteNamed', { name: item.name })} icon={<Trash2 size={15} />} disabled={locked} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ) : null,
    },
  ]

  return (
    <section className="site-dns-api-panel" aria-label={certT('dnsApi.title')}>
      <div className="site-groups-toolbar">
        {canManage ? <Button type="primary" icon={<Plus size={14} />} disabled={locked}
          onClick={() => { setWriteError(null); setEditor({ mode: 'create' }) }}>{certT('dnsApi.actions.create')}</Button> : null}
        {canManage ? (
          <Popconfirm title={certT('dnsApi.confirmDeleteSelected')} okText={certT('dnsApi.actions.delete')} cancelText={certT('dnsApi.actions.cancel')}
            okButtonProps={{ danger: true }} onConfirm={() => void deleteSelected()}>
            <Button danger icon={<Trash2 size={13} />} disabled={locked || selected.length === 0}>{certT('dnsApi.actions.deleteSelected')}</Button>
          </Popconfirm>
        ) : null}
        <span className="site-groups-count">{certT('dnsApi.total', { count: items.length })}</span>
      </div>
      {writeError && !editor && !uncertain ? <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} /> : null}
      {query.error ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={query.error instanceof ApiError ? errorMessage(query.error, t) : t('errors.request_failed')}
          action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      <Table rowKey="id" size="small" columns={columns} dataSource={pageItems} pagination={false} scroll={{ x: 900 }}
        loading={query.isPending || query.isFetching} locale={{ emptyText: query.isPending ? ' ' : certT('dnsApi.empty') }}
        rowSelection={canManage ? {
          selectedRowKeys: selected, onChange: (keys) => setSelected(keys.map(String)),
          getCheckboxProps: (item) => ({ disabled: platformManaged(item) }),
        } : undefined} />
      <div className="identity-pagination">
        <Pagination current={page} pageSize={limit} total={items.length} showSizeChanger pageSizeOptions={[10, 20, 50]}
          showTotal={(total) => certT('dnsApi.total', { count: total })}
          onChange={(next, size) => { setPage(size === limit ? next : 1); setLimit(size) }} />
      </div>
      <ProviderEditor sectioned editor={editor} isAdmin={false} pending={mutation.isPending} uncertain={uncertain}
        error={editor ? writeError : null} onCancel={closeAndRefresh} onSubmit={submit}
        onRetry={() => mutation.mutate()} onCloseAndRefresh={closeAndRefresh} />
    </section>
  )
}
