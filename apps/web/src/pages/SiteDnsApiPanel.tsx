import { useRef, useState } from 'react'
import { Button, Pagination, Popconfirm, Space, Table, Tooltip, type TableColumnsType } from 'antd'
import { CircleCheck, Pencil, Plus, Trash2 } from 'lucide-react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FeedbackWhen, OutcomeUnknown } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { dnsApi, ownDNSProviders, type CreateDNSProviderInput, type DNSProvider, type UpdateDNSProviderInput } from '../api/dns'
import { useSessionStore } from '../auth/session'
import TenantScopeSelect from '../components/TenantScopeSelect'
import '../i18n/dnsProviders'
import './SiteGroupsPage.css'
import {
  credentialFields, errorMessage, isCreatableProviderType, ProviderEditor, providerLabel,
  type DNSProviderEditorState, type ProviderForm,
} from './NodeDnsPage'

// DNS API（网站列表与证书管理两处共用，同一份数据）：
// 列 ID / 用户（仅管理员）/ 名称 / 类型 / 备注 / 操作，工具条「新增 DNS API」「删除选中」。
// 用户：本租户自己的 DNS 账号（/v1/dns/providers，服务端按 scope 隔离），不含平台 DNS 副本。
// 平台管理员：全部用户的 DNS 账号（managed_by=tenant，不含平台 DNS 副本），带所属用户，
// 可按用户筛选；新增时在弹窗里选用户（新增弹窗第一项「用户」）。
type Write =
  | { kind: 'create'; input: CreateDNSProviderInput }
  | { kind: 'update'; id: string; providerType: string; input: UpdateDNSProviderInput }
  | { kind: 'verify'; id: string; providerType: string; version: number }
  | { kind: 'delete'; id: string; version: number }
type Attempt = Write & { key: string }

const siteDnsApiQueryPrefix = 'site-dns-api'

function attemptKey(kind: Write['kind']): string {
  return `site-dns-api-${kind}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`
}

// 网络中断/超时/5xx 时结果未知，保留同一幂等键供重试。
function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

function clearCredentials(attempt: Attempt | null): void {
  const credentials = attempt?.kind === 'create' || attempt?.kind === 'update' ? attempt.input.credentials : undefined
  if (credentials) for (const key of Object.keys(credentials)) credentials[key] = ''
}

function hasPermission(permissions: string[] | undefined, code: string): boolean {
  return Boolean(permissions?.includes(code) || permissions?.includes('platform.admin'))
}

export default function SiteDnsApiPanel({ onChanged }: {
  // 写成功后通知宿主页刷新它自己的 DNS 账号缓存（证书页默认设置/申请弹窗的选择器）。
  onChanged?: () => void
} = {}) {
  const { t } = useTranslation('dnsProviders')
  const { t: certT } = useTranslation('certificates')
  const queryClient = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const accessToken = useSessionStore((state) => state.accessToken)
  const isPlatform = principal?.scope_kind === 'platform'
  const canManage = hasPermission(principal?.permissions, 'dns.manage')
  const canListUsers = hasPermission(principal?.permissions, 'identity.users.manage')
  const ownerKey = `${principal?.scope_kind}:${principal?.scope_id}:${principal?.user_id}:${sessionEpoch}`
  const [userFilter, setUserFilter] = useState('')
  const queryKey = [siteDnsApiQueryPrefix, principal?.scope_kind, principal?.scope_id, principal?.user_id, sessionEpoch, userFilter]
  const [editor, setEditor] = useState<DNSProviderEditorState | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const attemptRef = useRef<Attempt | null>(null)
  const [attempt, setAttempt] = useState<Attempt | null>(null)

  const token = (permission: string) => {
    const state = useSessionStore.getState()
    return state.accessToken && hasPermission(state.principal?.permissions, permission) ? state.accessToken : null
  }

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const current = useSessionStore.getState().principal
      const readToken = token('dns.read')
      if (!readToken || !current) throw new ApiError('permission denied', 403, 'permission_denied')
      const platform = current.scope_kind === 'platform'
      const value = await dnsApi.list(readToken, undefined, platform
        ? { managed_by: 'tenant', ...(userFilter ? { scope_id: userFilter } : {}) }
        : undefined)
      const items = ownDNSProviders(value.items)
      // 别人的账号不进列表与缓存：租户只收本 scope，平台按用户筛选时只收该用户。
      const expectedScope = platform ? userFilter : current.scope_id
      if (expectedScope && items.some((item) => item.scope_id !== expectedScope)) {
        throw new ApiError('DNS provider list response was invalid', 502, 'invalid_response')
      }
      return items
    },
  })
  const refreshAll = async () => {
    await queryClient.invalidateQueries({ queryKey: [siteDnsApiQueryPrefix] })
    onChanged?.()
  }

  const mutation = useMutation<void, unknown, void>({
    mutationFn: async () => {
      const frozen = attemptRef.current
      const writeToken = token('dns.manage')
      if (!frozen || !writeToken) throw new ApiError('permission denied', 403, 'permission_denied')
      if (frozen.kind === 'create') await dnsApi.create(writeToken, frozen.input, frozen.key)
      else if (frozen.kind === 'update') await dnsApi.update(writeToken, frozen.id, frozen.providerType, frozen.input, frozen.key)
      else if (frozen.kind === 'verify') await dnsApi.verify(writeToken, frozen.id, frozen.providerType, frozen.version, frozen.key)
      else await dnsApi.remove(writeToken, frozen.id, frozen.version, frozen.key)
    },
    onSuccess: async () => {
      clearCredentials(attemptRef.current)
      attemptRef.current = null
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      await refreshAll()
    },
    onError: (error) => {
      const apiError = error instanceof ApiError ? error : new ApiError('request failed')
      setWriteError(apiError)
      if (!outcomeUnknown(error)) {
        clearCredentials(attemptRef.current)
        attemptRef.current = null
        setAttempt(null)
        if (apiError.code === 'version_conflict' || apiError.code === 'dns_resource_not_found') {
          setEditor(null)
          void query.refetch()
        }
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
      const target = values.target_scope_id?.trim()
      if (isPlatform && !target) return
      const credentials = Object.fromEntries(credentialFields[values.provider_type].map((field) => [field.name, values.credentials[field.name]]))
      start({ kind: 'create', input: {
        ...(isPlatform ? { target_scope_id: target } : {}),
        name: values.name.trim(), remark: (values.remark ?? '').trim(), provider_type: values.provider_type, credentials,
      } })
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
    const writeToken = token('dns.manage')
    if (!writeToken) return
    try {
      for (const item of items.filter((value) => selected.includes(value.id))) {
        await dnsApi.remove(writeToken, item.id, item.version, attemptKey('delete'))
      }
      setSelected([])
    } catch (error) {
      setWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
    }
    await refreshAll()
  }
  const items = query.data ?? []
  const pageItems = items.slice((page - 1) * limit, page * limit)
  const locked = mutation.isPending || attempt !== null
  const uncertain = attempt !== null && writeError !== null && outcomeUnknown(writeError)
  const userPicker = (props: { value?: string; onChange?: (value: string) => void; disabled?: boolean; allowClear?: boolean; label: string; placeholder: string }) => (
    <TenantScopeSelect accessToken={accessToken} ownerKey={ownerKey} canList={canListUsers} queryKeyPrefix="site-dns-api-users"
      value={props.value ?? ''} onChange={(next) => props.onChange?.(next)} disabled={props.disabled} allowClear={props.allowClear}
      ariaLabel={props.label} placeholder={props.placeholder} emptyText={certT('dnsApi.userEmpty')} />
  )
  const columns: TableColumnsType<DNSProvider> = [
    { title: 'ID', dataIndex: 'id', width: 300, ellipsis: true },
    ...(isPlatform ? [{
      title: certT('dnsApi.columns.user'), key: 'owner', width: 180, ellipsis: true,
      render: (_: unknown, item: DNSProvider) => item.owner ? `${item.owner.username}（${item.owner.display_id}）` : '—',
    }] : []),
    { title: certT('dnsApi.columns.name'), dataIndex: 'name', ellipsis: true },
    { title: certT('dnsApi.columns.type'), dataIndex: 'provider_type', width: 200, render: (value: string) => providerLabel(value, t) },
    {
      title: certT('dnsApi.columns.remark'), key: 'remark', ellipsis: true,
      // 不设状态列：停用/待验证跟在备注后（证书页原有写法），建站选择器只列已验证的。
      render: (_, item) => {
        const remark = item.remark?.trim()
        const state = item.status === 'verified' ? '' : t(`states.${item.status}`)
        if (state) return remark ? `${remark}（${state}）` : state
        return remark || '—'
      },
    },
    {
      title: certT('dnsApi.columns.actions'), key: 'actions', width: 140, fixed: 'right',
      render: (_, item) => canManage ? (
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
        {isPlatform ? (
          <div className="site-dns-api-user-filter">
            {userPicker({ value: userFilter, allowClear: true, label: certT('dnsApi.userFilter'), placeholder: certT('dnsApi.userFilterPlaceholder'),
              onChange: (next) => { setUserFilter(next); setSelected([]); setPage(1) } })}
          </div>
        ) : null}
        <span className="site-groups-count">{certT('dnsApi.total', { count: items.length })}</span>
      </div>
      {uncertain && !editor ? (
        <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space size={4}>
          <Button size="small" loading={mutation.isPending} onClick={() => mutation.mutate()}>{t('actions.retrySameRequest')}</Button>
          <Button size="small" onClick={closeAndRefresh}>{t('actions.closeAndRefresh')}</Button>
        </Space>} className="identity-alert" />
      ) : writeError && !editor ? <FeedbackWhen title={errorMessage(writeError, t)} onClose={() => setWriteError(null)} /> : null}
      {query.error ? (
        <FeedbackWhen title={t('errors.loadFailed')} detail={query.error instanceof ApiError ? errorMessage(query.error, t) : t('errors.request_failed')}
          action={<Button size="small" onClick={() => void query.refetch()}>{t('actions.retry')}</Button>} />
      ) : null}
      <Table rowKey="id" size="small" columns={columns} dataSource={pageItems} pagination={false} scroll={{ x: 900 }}
        loading={query.isPending || query.isFetching} locale={{ emptyText: query.isPending ? ' ' : certT('dnsApi.empty') }}
        rowSelection={canManage ? {
          selectedRowKeys: selected, onChange: (keys) => setSelected(keys.map(String)),
        } : undefined} />
      <div className="identity-pagination">
        <Pagination current={page} pageSize={limit} total={items.length} showSizeChanger pageSizeOptions={[10, 20, 50]}
          showTotal={(total) => certT('dnsApi.total', { count: total })}
          onChange={(next, size) => { setPage(size === limit ? next : 1); setLimit(size) }} />
      </div>
      <ProviderEditor sectioned editor={editor} isAdmin={isPlatform} pending={mutation.isPending} uncertain={uncertain}
        error={editor ? writeError : null} onCancel={closeAndRefresh} onSubmit={submit}
        onRetry={() => mutation.mutate()} onCloseAndRefresh={closeAndRefresh}
        defaultTargetScope={userFilter}
        targetScopeInput={(props) => userPicker({ ...props, label: t('editor.targetScope'), placeholder: t('editor.targetScopePlaceholder') })} />
    </section>
  )
}
