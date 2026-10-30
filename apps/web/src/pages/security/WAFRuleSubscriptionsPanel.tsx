import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Drawer, Form, Input, InputNumber, Modal, Popconfirm, Space, Switch, Table, Tag, Tooltip, type TableColumnsType } from 'antd'
import { useFeedbackMessage, useFeedback } from '@cdnca/ui'
import { Pencil, Plus, RefreshCw, Trash2, Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../../api/auth'
import {
  rulePackSiteLink,
  subscriptionURLProblem,
  wafRuleSubscriptionsApi,
  type WAFRuleSubscription,
  type WAFRuleSubscriptionInput,
  type WAFSubscriptionPack,
} from '../../api/wafRuleSubscriptions'
import { localizedUnknownApiError } from '../../i18n/apiError'
import { formatDateTime } from '../../i18n/formatters'
import '../../i18n/wafRuleSubscriptions'

const defaultInput: WAFRuleSubscriptionInput = { name: '', description: '', source_url: '', interval_minutes: 360, enabled: true }

// WAFRuleSubscriptionsPanel is the platform operator's "规则库订阅" drawer:
// subscription URLs, their last good snapshot and "立即更新", and per
// subscription the subscribers' rule packs with the sites waiting to be
// published on a new version (PA-25).
export default function WAFRuleSubscriptionsPanel({ accessToken, open, onClose, onChanged }: {
  accessToken: string
  open: boolean
  onClose: () => void
  onChanged?: () => void
}) {
  const { t } = useTranslation('securityPolicies')
  const queryClient = useQueryClient()
  const [messageApi, messageContext] = useFeedbackMessage()
  const feedback = useFeedback()
  const [editing, setEditing] = useState<WAFRuleSubscription | 'create' | null>(null)
  const [form] = Form.useForm<WAFRuleSubscriptionInput>()
  const query = useQuery({ queryKey: ['waf-rule-subscriptions'], enabled: open, queryFn: () => wafRuleSubscriptionsApi.list(accessToken) })
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['waf-rule-subscriptions'] })
    onChanged?.()
  }
  const failure = (error: unknown) => {
    // responseApiError keeps no server text, so a refused save is localized.
    const text = t(error instanceof ApiError && error.status === 400 ? 'wafSubscriptions.notices.invalid' : 'wafSubscriptions.notices.failed')
    void feedback.error(localizedUnknownApiError(error, text))
  }
  const save = useMutation({
    mutationFn: (input: WAFRuleSubscriptionInput) => editing && editing !== 'create'
      ? wafRuleSubscriptionsApi.update(accessToken, editing.id, input)
      : wafRuleSubscriptionsApi.create(accessToken, input),
    onSuccess: () => {
      void messageApi.success(t(editing === 'create' ? 'wafSubscriptions.notices.created' : 'wafSubscriptions.notices.updated'))
      setEditing(null)
      refresh()
    },
    onError: failure,
  })
  const remove = useMutation({
    mutationFn: (id: string) => wafRuleSubscriptionsApi.remove(accessToken, id),
    onSuccess: () => { void messageApi.success(t('wafSubscriptions.notices.removed')); refresh() },
    onError: failure,
  })
  const sync = useMutation({
    mutationFn: (id: string) => wafRuleSubscriptionsApi.sync(accessToken, id),
    onSuccess: (item) => {
      if (item.last_error) void feedback.warning(t('wafSubscriptions.notices.syncFailed', { error: item.last_error }))
      else void messageApi.success(t('wafSubscriptions.notices.synced'))
      refresh()
    },
    onError: failure,
  })
  const openEditor = (item: WAFRuleSubscription | 'create') => {
    setEditing(item)
    form.setFieldsValue(item === 'create' ? defaultInput : {
      name: item.name, description: item.description, source_url: item.source_url,
      interval_minutes: item.interval_minutes, enabled: item.enabled,
    })
  }
  const time = (value: string | null) => value ? formatDateTime(value) : t('wafSubscriptions.values.never')
  const columns: TableColumnsType<WAFRuleSubscription> = [
    { title: t('wafSubscriptions.columns.name'), dataIndex: 'name', render: (_, item) => <span><strong>{item.name}</strong>{item.description ? <><br /><small>{item.description}</small></> : null}</span> },
    { title: t('wafSubscriptions.columns.url'), dataIndex: 'source_url', ellipsis: true, render: (value: string) => <Tooltip title={value}><code>{value}</code></Tooltip> },
    { title: t('wafSubscriptions.columns.interval'), dataIndex: 'interval_minutes', render: (value: number, item) => <span>{t('wafSubscriptions.values.minutes', { count: value })}<br /><Tag color={item.enabled ? 'blue' : 'default'}>{t(item.enabled ? 'wafSubscriptions.values.enabled' : 'wafSubscriptions.values.paused')}</Tag></span> },
    { title: t('wafSubscriptions.columns.state'), key: 'state', render: (_, item) => {
      const state = item.last_error ? 'failed' : item.last_success_at ? 'ok' : 'pending'
      const tag = <Tag color={state === 'failed' ? 'error' : state === 'ok' ? 'success' : 'default'}>{t(`wafSubscriptions.values.${state}`)}</Tag>
      return item.last_error ? <Tooltip title={item.last_error}>{tag}<small className="waf-subscription-error">{item.last_error}</small></Tooltip> : tag
    } },
    { title: t('wafSubscriptions.columns.version'), key: 'version', render: (_, item) => item.revision > 0
      ? <span>{item.feed_version}<br /><small>{t('wafSubscriptions.values.revision', { revision: item.revision })}</small>
        <br /><small>{t('wafSubscriptions.values.packVersion', { version: `${item.revision}.x` })}</small></span> : '—' },
    { title: t('wafSubscriptions.columns.rules'), dataIndex: 'rule_count' },
    { title: t('wafSubscriptions.columns.lastSuccess'), dataIndex: 'last_success_at', render: (value: string | null) => time(value) },
    { title: t('wafSubscriptions.columns.nextFetch'), dataIndex: 'next_fetch_at', render: (value: string, item) => item.enabled ? formatDateTime(value) : '—' },
    { title: t('wafSubscriptions.columns.subscribers'), dataIndex: 'subscribers' },
    { title: t('wafSubscriptions.columns.pending'), dataIndex: 'pending_sites', render: (value: number) => value > 0
      ? <Tag color="warning">{value}</Tag> : value },
    { title: t('wafSubscriptions.columns.actions'), key: 'actions', render: (_, item) => <Space size={4}>
      <Button size="small" icon={<RefreshCw size={13} />} loading={sync.isPending && sync.variables === item.id} onClick={() => sync.mutate(item.id)}>{t('wafSubscriptions.syncNow')}</Button>
      <Button size="small" icon={<Pencil size={13} />} aria-label={t('wafSubscriptions.edit')} onClick={() => openEditor(item)} />
      <Popconfirm title={t('wafSubscriptions.removeConfirm')} onConfirm={() => remove.mutate(item.id)}>
        <Button size="small" danger icon={<Trash2 size={13} />} aria-label={t('wafSubscriptions.remove')} />
      </Popconfirm>
    </Space> },
  ]
  const pendingSites = (query.data ?? []).reduce((total, item) => total + item.pending_sites, 0)
  return <Drawer title={t('wafSubscriptions.title')} open={open} onClose={onClose} width={1180} destroyOnHidden>
    {messageContext}
    <Alert type="info" showIcon message={t('wafSubscriptions.intro')} description={t('wafSubscriptions.limits')} style={{ marginBottom: 12 }} />
    {pendingSites > 0 ? <Alert type="warning" showIcon role="status" style={{ marginBottom: 12 }}
      message={t('wafSubscriptions.packs.pendingAlert', { count: pendingSites })} /> : null}
    <Space style={{ marginBottom: 12 }}>
      <Button type="primary" icon={<Plus size={14} />} onClick={() => openEditor('create')}>{t('wafSubscriptions.add')}</Button>
      <Button icon={<RefreshCw size={14} />} loading={query.isFetching} onClick={() => void query.refetch()} aria-label={t('wafSubscriptions.refresh')} />
    </Space>
    <Table rowKey="id" size="small" columns={columns} dataSource={query.data ?? []} loading={query.isPending} pagination={false}
      expandable={{ rowExpandable: (item) => item.subscribers > 0, expandedRowRender: (item) => <SubscriberPacks accessToken={accessToken} subscription={item} /> }} />
    <Modal title={t(editing === 'create' ? 'wafSubscriptions.add' : 'wafSubscriptions.edit')} open={editing !== null}
      confirmLoading={save.isPending} onCancel={() => setEditing(null)} onOk={() => void form.validateFields().then((values) => save.mutate(values)).catch(() => undefined)} destroyOnHidden>
      <Form form={form} layout="vertical" requiredMark={false} initialValues={defaultInput}>
        <Form.Item name="name" label={t('wafSubscriptions.fields.name')} rules={[{ required: true, whitespace: true, max: 128 }]}><Input /></Form.Item>
        <Form.Item name="source_url" label={t('wafSubscriptions.fields.url')} rules={[{ required: true }, {
          validator: (_, value: string) => {
            const problem = value ? subscriptionURLProblem(value) : null
            return problem ? Promise.reject(new Error(t(`wafSubscriptions.urlProblems.${problem}`))) : Promise.resolve()
          },
        }]}><Input placeholder={t('wafSubscriptions.fields.urlPlaceholder')} /></Form.Item>
        <Form.Item name="interval_minutes" label={t('wafSubscriptions.fields.interval')} extra={t('wafSubscriptions.fields.intervalHelp')} rules={[{ required: true }]}>
          <InputNumber min={5} max={10080} precision={0} style={{ width: 180 }} />
        </Form.Item>
        <Form.Item name="enabled" label={t('wafSubscriptions.fields.enabled')} valuePropName="checked"><Switch /></Form.Item>
        <Form.Item name="description" label={t('wafSubscriptions.fields.description')} rules={[{ max: 500 }]}><Input.TextArea rows={2} /></Form.Item>
      </Form>
    </Modal>
  </Drawer>
}

// SubscriberPacks lists the subscribers' rule packs of one subscription and
// the published sites still on an older version. "去发布" opens the site on
// the rule pack page; nothing is published from here.
function SubscriberPacks({ accessToken, subscription }: { accessToken: string; subscription: WAFRuleSubscription }) {
  const { t } = useTranslation('securityPolicies')
  const query = useQuery({
    queryKey: ['waf-rule-subscriptions', 'packs', subscription.id],
    queryFn: () => wafRuleSubscriptionsApi.packs(accessToken, subscription.id),
  })
  const columns: TableColumnsType<WAFSubscriptionPack> = [
    { title: t('wafSubscriptions.packs.tenant'), dataIndex: 'tenant_name', render: (value: string, pack) => value || pack.tenant_scope_id },
    { title: t('wafSubscriptions.packs.pack'), dataIndex: 'pack_id', render: (value: string) => <code>{value}</code> },
    { title: t('wafSubscriptions.packs.version'), key: 'version', render: (_, pack) => `${pack.current_version || '—'} / ${pack.latest_version || '—'}` },
    { title: t('wafSubscriptions.packs.policy'), dataIndex: 'update_policy', render: (value: string) => t(`wafSubscriptions.packs.${value === 'manual' ? 'manual' : 'auto'}`) },
    { title: t('wafSubscriptions.packs.pending'), key: 'pending', render: (_, pack) => pack.pending_sites.length === 0
      ? t('wafSubscriptions.packs.noPending')
      : <Space wrap size={4}>{pack.pending_sites.map((site) => <Tag key={site.site_id} color="warning">
        {t('wafSubscriptions.packs.pendingTag', { domain: site.domain, version: site.published_version })}
        {' '}<Link to={rulePackSiteLink(site.site_id)}><Upload size={12} /> {t('wafSubscriptions.packs.publish')}</Link>
      </Tag>)}</Space> },
  ]
  return <Table rowKey="pack_id" size="small" columns={columns} dataSource={query.data ?? []} loading={query.isPending} pagination={false}
    locale={{ emptyText: t('wafSubscriptions.packs.none') }} />
}
