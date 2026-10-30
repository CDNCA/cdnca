import { useEffect, useRef, useState } from 'react'
import { Button, Form, Input, Modal, Pagination, Popconfirm, Radio, Select, Space, Table, Tag, type TableColumnsType } from 'antd'
import { CircleCheck, CircleX, Pencil, Plus, Trash2 } from 'lucide-react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { FeedbackWhen } from '@cdnca/ui'

import { ApiError } from '../api/auth'
import { dnsApi } from '../api/dns'
import { securityPoliciesApi } from '../api/securityPolicies'
import { siteGroupsApi } from '../api/siteGroups'
import { siteTLSCustomCipherSuites } from '../api/sites'
import {
  siteDefaultDocuments, siteDefaultPolicyKinds, siteDefaultSettingNames, siteDefaultsApi, siteDefaultSwitches,
  type CreateSiteDefaultInput, type SiteDefaultSettingName, type SiteUserDefault,
} from '../api/siteDefaults'
import { useSessionStore } from '../auth/session'
import { siteDefaultValueError } from './siteDefaultValue'
import { CacheRulesDefaultEditor, CondOriginDefaultEditor } from './SiteDefaultDocumentEditors'
import '../i18n/siteListTabs'

// 网站列表 > 默认设置（用户端）：租户给自己新建网站设的默认值。
// 只影响之后新建的网站；新建时手动填写的值优先（后端 /v1/site-defaults，迁移 490）。

const balanceWays = ['round_robin', 'ip_hash', 'url_hash', 'least_conn', 'random'] as const
// 单选类设置项的取值（与后端 normalizeSiteDefaultValue 一致）
const choiceValues: Partial<Record<SiteDefaultSettingName, readonly string[]>> = {
  balance_way: balanceWays,
  ssl_cipher_preset: ['modern', 'compatible', 'legacy', 'custom'],
  origin_protocol: ['http', 'https', 'follow'],
  // 区域屏蔽预设：block_region 取值（拼写保持原样）
  block_region: ['none', 'abrord_inc', 'abrord_no_inc', 'china_inc', 'china_not_inc'],
}
// 规则文档默认（网站缓存 / 条件源站）在列表里显示规则条数
function documentRuleCount(value: string): number {
  try {
    const parsed = JSON.parse(value) as { rules?: unknown[]; routes?: unknown[] }
    return (parsed.rules ?? parsed.routes ?? []).length
  } catch { return 0 }
}
// 有说明文字的设置项（defaults.hints）
const hintedSettings: ReadonlySet<SiteDefaultSettingName> = new Set(['cc_ban_seconds', 'cc_pass_seconds', 'gzip_enable', 'dns_provider', 'ipv6_enable',
  'cc_policy', 'waf_policy', 'acl_policy', 'block_proxy', 'req_header', 'post_size_limit',
  'http2', 'http3', 'ssl_prefer_server_ciphers', 'proxy_cache', 'cond_origin', 'block_region', 'ssl_cipher_preset', 'ssl_cipher_suites'])
const initialValues: Partial<Record<SiteDefaultSettingName, string>> = {
  // 规则文档默认从空规则开始，在可视化编辑器里逐条添加
  proxy_cache: JSON.stringify({ mode: 'override', rules: [], query_mode: 'preserve', query_names: [], vary_headers: [], disk_quota_bytes: 1_073_741_824 }),
  cond_origin: JSON.stringify({ routes: [] }),
  // 自定义套件从现代预设的 6 个 AEAD 套件开始
  ssl_cipher_suites: siteTLSCustomCipherSuites.slice(0, 6).join(':'),
  balance_way: 'round_robin', ssl_cipher_preset: 'modern', block_region: 'abrord_inc', origin_protocol: 'http', ssl_protocols: 'TLSv1.2 TLSv1.3',
}

// #11 自定义套件：表单值是冒号分隔串，这里按白名单多选（保持所选顺序）
function CipherSuitesInput({ value, onChange, disabled, label }: { value?: string; onChange?: (value: string) => void; disabled?: boolean; label: string }) {
  return (
    <Select<string[]> mode="multiple" aria-label={label} disabled={disabled}
      value={(value ?? '').split(':').filter(Boolean)}
      options={siteTLSCustomCipherSuites.map((suite) => ({ value: suite, label: suite }))}
      onChange={(suites) => onChange?.(suites.join(':'))} />
  )
}

type Write =
  | { kind: 'create'; input: CreateSiteDefaultInput }
  | { kind: 'update'; item: SiteUserDefault; changes: { setting_value?: string; enabled?: boolean } }
  | { kind: 'delete'; item: SiteUserDefault }
type Attempt = Write & { key: string }
type BatchKind = 'enable' | 'disable' | 'delete'
// 批量：确认时冻结目标与逐项幂等键；结果未知的项保留原键重试，未执行的项
// 不发请求（SITE-CURRENT-03）。
type BatchItem = { item: SiteUserDefault; key: string; state: 'pending' | 'done' | 'unknown' | 'failed'; error?: ApiError }
type Batch = { kind: BatchKind; items: BatchItem[] }
type FormValues = { setting_name: SiteDefaultSettingName; setting_value: string; scope_name: 'global' | 'group'; group_id?: string }
type Editor = { mode: 'create' } | { mode: 'edit'; item: SiteUserDefault }

function writeKey(kind: string): string {
  return `site-default-${kind}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`
}

// 网络中断/超时/5xx：结果未知，保留同一幂等键重试。
function outcomeUnknown(error: unknown): boolean {
  return !(error instanceof ApiError) || error.status === 0 || error.status === 408 || error.status >= 500
}

export default function SiteDefaultsPanel() {
  const { t } = useTranslation('siteListTabs')
  const queryClient = useQueryClient()
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)
  const canManage = Boolean(principal?.permissions.includes('sites.manage'))
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(10)
  const [selected, setSelected] = useState<string[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const attemptRef = useRef<Attempt | null>(null)
  const [attempt, setAttempt] = useState<Attempt | null>(null)
  const [batch, setBatch] = useState<Batch | null>(null)
  const [batchRunning, setBatchRunning] = useState(false)
  const batchRunningRef = useRef(false)
  const [form] = Form.useForm<FormValues>()
  const settingName = Form.useWatch('setting_name', form)
  const scopeName = Form.useWatch('scope_name', form)
  const queryKey = ['site-defaults', principal?.scope_id, principal?.user_id, sessionEpoch, page, limit]

  const token = (permission: string) => {
    const state = useSessionStore.getState()
    return state.accessToken && state.principal?.permissions.includes(permission) ? state.accessToken : null
  }

  const query = useQuery({
    queryKey,
    queryFn: async () => {
      const accessToken = token('sites.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      return siteDefaultsApi.list(accessToken, page, limit)
    },
  })
  // SITE-CURRENT-06：分组分页加载（与建站表单同一查询方式），失败给重试。
  const groups = useInfiniteQuery({
    queryKey: ['site-defaults-groups', principal?.scope_id, sessionEpoch],
    enabled: editor !== null && principal?.scope_kind === 'tenant',
    initialPageParam: 1,
    queryFn: async ({ pageParam }) => {
      const accessToken = token('sites.read')
      if (!accessToken || !principal) throw new ApiError('permission denied', 403, 'permission_denied')
      return siteGroupsApi.list(accessToken, principal.scope_id, pageParam, 20)
    },
    getNextPageParam: (last) => last.page * last.limit < last.total ? last.page + 1 : undefined,
    retry: false,
  })
  const groupOptions = (groups.data?.pages.flatMap((value) => value.items) ?? []).filter((item) => !item.deleted_at)
  // 默认设置 > DNS API：只列本人已验证的账号（后端保存时再核对归属与状态）
  const dnsProviders = useQuery({
    queryKey: ['site-defaults-dns-providers', principal?.scope_id, sessionEpoch],
    // 列表里有该项（显示账号名）或正在编辑该项时读取
    enabled: Boolean(token('dns.read')) && (settingName === 'dns_provider' ||
      (query.data?.items ?? []).some((item) => item.setting_name === 'dns_provider')),
    queryFn: async () => {
      const accessToken = token('dns.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      return dnsApi.list(accessToken)
    },
    retry: false,
  })
  // 默认设置 > 规则库（复制快照）：列本人的该类规则库，订阅的规则库不能复制（后端保存时再核对）
  const listedKinds = [...new Set((query.data?.items ?? []).map((item) => siteDefaultPolicyKinds[item.setting_name]).filter(Boolean))]
  const editingKind = settingName ? siteDefaultPolicyKinds[settingName] : undefined
  const policyKinds = [...new Set([...listedKinds, ...(editingKind ? [editingKind] : [])])] as Array<'cc' | 'waf' | 'acl'>
  const policies = useQuery({
    queryKey: ['site-defaults-policies', principal?.scope_id, sessionEpoch, policyKinds.join(',')],
    enabled: Boolean(token('security_policies.read')) && policyKinds.length > 0,
    queryFn: async () => {
      const accessToken = token('security_policies.read')
      if (!accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      const lists = await Promise.all(policyKinds.map((kind) => securityPoliciesApi.list(accessToken, { page: 1, limit: 100, kind })))
      return lists.flatMap((list) => list.items)
    },
    retry: false,
  })
  const policyNames = new Map((policies.data ?? []).map((item) => [item.id, item.name]))
  const policyOptions = (policies.data ?? []).filter((item) => !item.protected && item.kind === editingKind)
  const dnsOptions = (dnsProviders.data?.items ?? []).filter((item) => item.status === 'verified' && item.managed_by !== 'platform')
  const dnsNames = new Map((dnsProviders.data?.items ?? []).map((item) => [item.id, item.name]))

  useEffect(() => {
    if (!editor) return
    form.resetFields()
    form.setFieldsValue(editor.mode === 'create'
      ? { setting_name: 'http_listen_port', setting_value: '', scope_name: 'global' }
      : { setting_name: editor.item.setting_name, setting_value: editor.item.setting_value, scope_name: editor.item.scope_name,
          group_id: editor.item.group_id ?? undefined })
  }, [editor, form])

  const mutation = useMutation<void, unknown, void>({
    mutationFn: async () => {
      const frozen = attemptRef.current
      const accessToken = token('sites.manage')
      if (!frozen || !accessToken) throw new ApiError('permission denied', 403, 'permission_denied')
      if (frozen.kind === 'create') await siteDefaultsApi.create(accessToken, frozen.input, frozen.key)
      else if (frozen.kind === 'update') await siteDefaultsApi.update(accessToken, frozen.item, frozen.changes, frozen.key)
      else await siteDefaultsApi.remove(accessToken, frozen.item, frozen.key)
    },
    onSuccess: async () => {
      attemptRef.current = null
      setAttempt(null)
      setWriteError(null)
      setEditor(null)
      await queryClient.invalidateQueries({ queryKey: ['site-defaults'] })
    },
    onError: (error) => {
      setWriteError(error instanceof ApiError ? error : new ApiError('request failed'))
      if (!outcomeUnknown(error)) {
        attemptRef.current = null
        setAttempt(null)
      }
    },
  })

  const start = (next: Write) => {
    if (!token('sites.manage')) return
    const value = { ...next, key: writeKey(next.kind) } as Attempt
    attemptRef.current = value
    setAttempt(value)
    setWriteError(null)
    mutation.mutate()
  }

  // 批量启用 / 禁用 / 删除：只作用于当前页选中项（翻页、改每页条数清空选择，
  // SITE-CURRENT-05）；逐条提交，遇到失败即停。确定失败的项与未执行的项
  // 可在结果里看到；结果未知的项用原幂等键重试（SITE-CURRENT-03）。
  const startBatch = (kind: BatchKind) => {
    if (batchRunningRef.current || !token('sites.manage')) return
    const targets = items.filter((value) => selected.includes(value.id) &&
      (kind === 'delete' || value.enabled !== (kind === 'enable')))
    if (targets.length === 0) {
      setSelected([])
      return
    }
    void runBatch({ kind, items: targets.map((item) => ({ item, key: writeKey(kind === 'delete' ? 'delete' : 'update'), state: 'pending' })) })
  }
  const runBatch = async (frozen: Batch) => {
    if (batchRunningRef.current) return
    batchRunningRef.current = true
    setBatchRunning(true)
    setWriteError(null)
    const next: Batch = { ...frozen, items: frozen.items.map((value) => ({ ...value })) }
    setBatch(next)
    for (const value of next.items) {
      if (value.state === 'done' || value.state === 'failed') continue
      const accessToken = token('sites.manage')
      if (!accessToken) break
      try {
        if (frozen.kind === 'delete') await siteDefaultsApi.remove(accessToken, value.item, value.key)
        else await siteDefaultsApi.update(accessToken, value.item, { enabled: frozen.kind === 'enable' }, value.key)
        value.state = 'done'
        value.error = undefined
      } catch (error) {
        value.error = error instanceof ApiError ? error : new ApiError('request failed')
        value.state = outcomeUnknown(error) ? 'unknown' : 'failed'
        setBatch({ ...next, items: [...next.items] })
        break
      }
      setBatch({ ...next, items: [...next.items] })
    }
    batchRunningRef.current = false
    setBatchRunning(false)
    if (next.items.every((value) => value.state === 'done')) {
      setBatch(null)
      setSelected([])
    }
    await queryClient.invalidateQueries({ queryKey: ['site-defaults'] })
  }
  const batchUnknown = batch?.items.some((value) => value.state === 'unknown') ?? false

  const submit = (values: FormValues) => {
    if (!editor) return
    const value = values.setting_value.trim()
    if (editor.mode === 'edit') {
      start({ kind: 'update', item: editor.item, changes: { setting_value: value } })
      return
    }
    start({ kind: 'create', input: {
      setting_name: values.setting_name, setting_value: value, scope_name: values.scope_name,
      ...(values.scope_name === 'group' ? { group_id: values.group_id ?? null } : {}),
    } })
  }

  const displayValue = (item: Pick<SiteUserDefault, 'setting_name' | 'setting_value'>) => {
    if (siteDefaultSwitches.has(item.setting_name)) return item.setting_value === '1' ? t('defaults.form.on') : t('defaults.form.off')
    if (choiceValues[item.setting_name]) return t(`defaults.choices.${item.setting_name}.${item.setting_value}`, { defaultValue: item.setting_value })
    if (item.setting_name === 'dns_provider') return dnsNames.get(item.setting_value) ?? item.setting_value
    if (siteDefaultPolicyKinds[item.setting_name]) return policyNames.get(item.setting_value) ?? item.setting_value
    if (item.setting_name === 'post_size_limit') return t('defaults.form.megabytes', { value: item.setting_value })
    if (item.setting_name === 'req_header') return <span style={{ whiteSpace: 'pre-line' }}>{item.setting_value}</span>
    if (siteDefaultDocuments.has(item.setting_name)) return t('defaults.form.ruleCount', { count: documentRuleCount(item.setting_value) })
    return item.setting_value
  }

  const items = query.data?.items ?? []
  const total = query.data?.total ?? 0
  const locked = mutation.isPending || attempt !== null || batchRunning || batchUnknown
  const uncertain = attempt !== null && writeError !== null && outcomeUnknown(writeError)
  // SITE-CURRENT-08：按错误类型给出下一步
  const errorText = (error: ApiError) => {
    if (error.code === 'site_default_conflict') return t('defaults.errors.conflict')
    if (error.code === 'site_default_policy_unusable') return t('defaults.errors.policyUnusable')
    if (error.status === 403) return t('defaults.errors.forbidden')
    if (error.status === 404) return t('defaults.errors.notFound')
    if (error.status === 409 || error.status === 412 || error.code === 'version_conflict') return t('defaults.errors.versionConflict')
    if (error.status === 400 || error.status === 422) return t('defaults.errors.invalid')
    if (outcomeUnknown(error)) return t('defaults.errors.unknown')
    return t('defaults.errors.writeFailed')
  }
  // SITE-CURRENT-04：请求中或结果未知时，X、Esc、遮罩与取消一样不能关闭
  const closeEditor = () => {
    if (mutation.isPending || uncertain) return
    attemptRef.current = null
    setAttempt(null)
    setWriteError(null)
    setEditor(null)
  }
  const columns: TableColumnsType<SiteUserDefault> = [
    { title: t('defaults.columns.id'), dataIndex: 'display_id', width: 80 },
    { title: t('defaults.columns.name'), dataIndex: 'setting_name', render: (value: SiteDefaultSettingName) => t(`defaults.names.${value}`) },
    { title: t('defaults.columns.value'), key: 'value', render: (_, item) => displayValue(item) },
    {
      title: t('defaults.columns.scope'), key: 'scope',
      render: (_, item) => item.scope_name === 'group' ? t('defaults.scope.group', { name: item.group_name ?? item.group_id }) : t('defaults.scope.global'),
    },
    {
      title: t('defaults.columns.state'), dataIndex: 'enabled', width: 90,
      render: (value: boolean) => <Tag color={value ? 'success' : 'default'}>{value ? t('defaults.state.enabled') : t('defaults.state.disabled')}</Tag>,
    },
    {
      title: t('defaults.columns.actions'), key: 'actions', width: 120,
      render: (_, item) => canManage ? (
        <Space size={2}>
          <Button type="text" size="small" aria-label={`${t('defaults.actions.edit')} ${t(`defaults.names.${item.setting_name}`)}`}
            icon={<Pencil size={15} />} disabled={locked} onClick={() => { setWriteError(null); setEditor({ mode: 'edit', item }) }} />
          <Popconfirm title={t('defaults.confirmDelete', { count: 1 })} okText={t('defaults.actions.delete')} cancelText={t('defaults.actions.cancel')}
            okButtonProps={{ danger: true }} onConfirm={() => start({ kind: 'delete', item })}>
            <Button danger type="text" size="small" aria-label={`${t('defaults.actions.delete')} ${t(`defaults.names.${item.setting_name}`)}`}
              icon={<Trash2 size={15} />} disabled={locked} />
          </Popconfirm>
        </Space>
      ) : null,
    },
  ]
  const isSwitch = settingName ? siteDefaultSwitches.has(settingName) : false

  return (
    <section className="site-defaults-panel" aria-labelledby="site-defaults-title">
      <header className="site-defaults-header">
        <h2 id="site-defaults-title">{t('defaults.title')}</h2>
        <p>{t('defaults.description')}</p>
      </header>
      {canManage ? (
        <div className="site-groups-toolbar">
          <Button type="primary" icon={<Plus size={14} />} disabled={locked}
            onClick={() => { setWriteError(null); setEditor({ mode: 'create' }) }}>{t('defaults.actions.create')}</Button>
          <Popconfirm title={t('defaults.confirmDelete', { count: selected.length })} okText={t('defaults.actions.delete')}
            cancelText={t('defaults.actions.cancel')} okButtonProps={{ danger: true }} onConfirm={() => startBatch('delete')}>
            <Button danger icon={<Trash2 size={13} />} disabled={locked || selected.length === 0}>{t('defaults.actions.delete')}</Button>
          </Popconfirm>
          <Button icon={<CircleCheck size={13} />} disabled={locked || selected.length === 0} onClick={() => startBatch('enable')}>
            {t('defaults.actions.enable')}
          </Button>
          <Button icon={<CircleX size={13} />} disabled={locked || selected.length === 0} onClick={() => startBatch('disable')}>
            {t('defaults.actions.disable')}
          </Button>
        </div>
      ) : null}
      {writeError && !editor ? <FeedbackWhen title={errorText(writeError)} onClose={() => setWriteError(null)} /> : null}
      {batch && !batchRunning ? (
        <FeedbackWhen
          title={t(`defaults.batch.${batchUnknown ? 'unknown' : 'stopped'}`, { action: t(`defaults.actions.${batch.kind}`) })}
          detail={<ul className="site-defaults-batch-result">{batch.items.map((value) => (
            <li key={value.item.id}>
              {t(`defaults.names.${value.item.setting_name}`)}（{value.item.display_id}）：{t(`defaults.batch.state.${value.state}`)}
              {value.error ? ` ${errorText(value.error)}` : ''}
            </li>
          ))}</ul>}
          action={batchUnknown ? <Button size="small" onClick={() => void runBatch(batch)}>{t('defaults.actions.retrySame')}</Button> : undefined}
          onClose={batchUnknown ? undefined : () => setBatch(null)}
        />
      ) : null}
      {query.error ? (
        <FeedbackWhen title={t('defaults.errors.loadFailed')}
          action={<Button size="small" onClick={() => void query.refetch()}>{t('defaults.actions.retry')}</Button>} />
      ) : null}
      <Table rowKey="id" size="small" columns={columns} dataSource={items} pagination={false}
        loading={query.isPending || query.isFetching} locale={{ emptyText: query.isPending ? ' ' : t('defaults.empty') }}
        rowSelection={canManage ? { selectedRowKeys: selected, getCheckboxProps: () => ({ disabled: locked }), onChange: (keys) => setSelected(keys.map(String)) } : undefined} />
      <div className="identity-pagination">
        <Pagination current={page} pageSize={limit} total={total} showSizeChanger pageSizeOptions={[10, 20, 50]}
          showTotal={(count) => t('defaults.total', { count })}
          onChange={(next, size) => { setPage(size === limit ? next : 1); setLimit(size); setSelected([]) }} />
      </div>
      <Modal className="identity-modal" open={editor !== null} width={settingName && siteDefaultDocuments.has(settingName) ? 760 : 560} destroyOnHidden
        title={editor?.mode === 'edit' ? t('defaults.form.editTitle') : t('defaults.form.createTitle')}
        okText={uncertain ? t('defaults.actions.retry') : t('defaults.actions.save')} cancelText={t('defaults.actions.cancel')}
        confirmLoading={mutation.isPending} cancelButtonProps={{ disabled: mutation.isPending || uncertain }}
        closable={!mutation.isPending && !uncertain} maskClosable={!mutation.isPending && !uncertain} keyboard={!mutation.isPending && !uncertain}
        onCancel={closeEditor}
        onOk={() => uncertain ? mutation.mutate() : void form.validateFields().then(submit).catch(() => undefined)}>
        {writeError && editor ? <FeedbackWhen title={errorText(writeError)} /> : null}
        <Form form={form} layout="horizontal" labelCol={{ flex: '96px' }} requiredMark={false} disabled={mutation.isPending || uncertain}>
          <Form.Item name="setting_name" label={t('defaults.form.name')} rules={[{ required: true }]}>
            <Select disabled={editor?.mode === 'edit'} options={siteDefaultSettingNames.map((name) => ({ value: name, label: t(`defaults.names.${name}`) }))}
              onChange={(name: SiteDefaultSettingName) => form.setFieldValue('setting_value', siteDefaultSwitches.has(name) ? '1' : initialValues[name] ?? '')} />
          </Form.Item>
          <Form.Item name="setting_value" label={t('defaults.form.value')}
            extra={settingName && hintedSettings.has(settingName) ? t(`defaults.hints.${settingName}`) : undefined}
            rules={[{ required: true, whitespace: true, max: settingName && siteDefaultDocuments.has(settingName) ? 65_536 : settingName === 'req_header' ? 8192 : settingName === 'ssl_cipher_suites' ? 1024 : 256, message: t('defaults.form.invalid') }, {
              validator: (_, value?: string) => {
                const problem = siteDefaultValueError(settingName, value ?? '')
                return problem ? Promise.reject(new Error(t(`defaults.form.invalid_${problem}`))) : Promise.resolve()
              },
            }]}>
            {isSwitch ? (
              <Radio.Group options={[{ value: '1', label: t('defaults.form.on') }, { value: '0', label: t('defaults.form.off') }]} />
            ) : settingName === 'dns_provider' ? (
              <Select showSearch optionFilterProp="label" loading={dnsProviders.isFetching} placeholder={t('defaults.form.dnsProviderPlaceholder')}
                options={[
                  ...(editor?.mode === 'edit' && !dnsOptions.some((item) => item.id === editor.item.setting_value)
                    ? [{ value: editor.item.setting_value, label: dnsNames.get(editor.item.setting_value) ?? editor.item.setting_value }] : []),
                  ...dnsOptions.map((item) => ({ value: item.id, label: item.name })),
                ]}
                notFoundContent={dnsProviders.isError ? t('defaults.form.dnsProviderFailed') : t('defaults.form.dnsProviderEmpty')} />
            ) : editingKind ? (
              <Select showSearch optionFilterProp="label" loading={policies.isFetching} placeholder={t('defaults.form.policyPlaceholder')}
                options={[
                  ...(editor?.mode === 'edit' && !policyOptions.some((item) => item.id === editor.item.setting_value)
                    ? [{ value: editor.item.setting_value, label: policyNames.get(editor.item.setting_value) ?? editor.item.setting_value }] : []),
                  ...policyOptions.map((item) => ({ value: item.id, label: item.name })),
                ]}
                notFoundContent={policies.isError ? t('defaults.form.policyFailed') : t('defaults.form.policyEmpty')} />
            ) : settingName === 'proxy_cache' ? (
              <CacheRulesDefaultEditor disabled={mutation.isPending || uncertain} />
            ) : settingName === 'cond_origin' ? (
              <CondOriginDefaultEditor disabled={mutation.isPending || uncertain} />
            ) : settingName === 'ssl_cipher_suites' ? (
              <CipherSuitesInput label={t('defaults.names.ssl_cipher_suites')} disabled={mutation.isPending || uncertain} />
            ) : settingName === 'req_header' ? (
              <Input.TextArea autoComplete="off" rows={4} placeholder={t('defaults.form.reqHeaderPlaceholder')} />
            ) : settingName && choiceValues[settingName] ? (
              <Select options={choiceValues[settingName]!.map((value) => ({ value, label: t(`defaults.choices.${settingName}.${value}`) }))} />
            ) : (
              <Input autoComplete="off" placeholder={settingName?.endsWith('listen_port') ? t('defaults.form.portsPlaceholder')
                : settingName === 'backend_https_port' || settingName === 'backend_http_port' ? t('defaults.form.portPlaceholder')
                : settingName === 'ups_keepalive_timeout' ? t('defaults.form.timeoutPlaceholder')
                : settingName === 'origin_connect_timeout' || settingName === 'origin_read_timeout' ||
                  settingName === 'cc_ban_seconds' || settingName === 'cc_pass_seconds' ? t(`defaults.form.${settingName}Placeholder`)
                : settingName === 'post_size_limit' ? t('defaults.form.postSizePlaceholder')
                : settingName === 'ssl_protocols' ? t('defaults.form.protocolsPlaceholder') : undefined} />
            )}
          </Form.Item>
          <Form.Item name="scope_name" label={t('defaults.form.scope')}>
            <Radio.Group disabled={editor?.mode === 'edit'}
              options={[{ value: 'global', label: t('defaults.form.scopeGlobal') }, { value: 'group', label: t('defaults.form.scopeGroup') }]} />
          </Form.Item>
          {scopeName === 'group' ? (
            <Form.Item name="group_id" label={t('defaults.form.group')} rules={[{ required: true, message: t('defaults.form.groupRequired') }]}>
              <Select disabled={editor?.mode === 'edit'} placeholder={t('defaults.form.groupPlaceholder')} loading={groups.isFetching}
                showSearch optionFilterProp="label"
                options={[
                  ...(editor?.mode === 'edit' && editor.item.group_id && !groupOptions.some((group) => group.id === editor.item.group_id)
                    ? [{ value: editor.item.group_id, label: editor.item.group_name ?? editor.item.group_id }] : []),
                  ...groupOptions.map((group) => ({ value: group.id, label: group.name })),
                ]}
                notFoundContent={groups.isFetching ? t('defaults.form.groupLoading') : t('defaults.form.groupEmpty')}
                popupRender={(menu) => <>{menu}{groups.hasNextPage ? <Button block loading={groups.isFetchingNextPage} onClick={() => void groups.fetchNextPage()}>{t('defaults.form.groupMore')}</Button> : null}</>} />
            </Form.Item>
          ) : null}
          {scopeName === 'group' && groups.isError ? (
            <p role="alert" className="site-defaults-group-error">
              {(groups.error as ApiError | null)?.status === 403 ? t('defaults.form.groupForbidden') : t('defaults.form.groupFailed')}
              {' '}<Button size="small" onClick={() => void groups.refetch()}>{t('defaults.actions.retry')}</Button>
            </p>
          ) : null}
        </Form>
      </Modal>
    </section>
  )
}
