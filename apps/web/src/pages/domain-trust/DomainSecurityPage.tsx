import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Checkbox, Form, Input, Modal, Popconfirm, Radio, Result, Select, Space, Table, Tabs, Tag, Typography } from 'antd'
import { Download, Plus, ShieldOff, Upload } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import {
  domainBlocklistApi, domainSecurityPermission, newDomainTrustKey,
  type BlocklistEntry, type BlocklistHit, type BlocklistInput, type ClaimSuspension, type DomainOwnership, type OwnershipStatus,
} from '../../api/domainTrust'
import { sitesApi } from '../../api/sites'
import { useSessionStore } from '../../auth/session'
import '../../i18n/domainTrust'
import { useFeedback, FeedbackWhen } from '@cdnca/ui'

function codeOf(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

function useErrorText() {
  const { t } = useTranslation('domainTrust')
  return (error: unknown) => t(`errors.${codeOf(error)}`, { defaultValue: t('errors.failed', { code: codeOf(error) }) })
}

function date(value?: string) {
  return value ? new Date(value).toLocaleString() : '-'
}

function EntryModal({ entry, onClose }: { entry: BlocklistEntry | null; onClose: () => void }) {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [form] = Form.useForm<BlocklistInput>()
  const save = useMutation({
    mutationFn: (input: BlocklistInput) => entry
      ? domainBlocklistApi.update(token, entry.id, entry.revision, input, newDomainTrustKey('blocklist-update'))
      : domainBlocklistApi.create(token, input, newDomainTrustKey('blocklist-create')),
    onSuccess: () => {
      void message.success(t('blocklist.saved'))
      void client.invalidateQueries({ queryKey: ['domainBlocklist'] })
      onClose()
    },
  })
  return (
    <Modal open title={entry ? t('blocklist.edit') : t('blocklist.add')} okText={t('blocklist.save')} cancelText={t('blocklist.cancel')}
      confirmLoading={save.isPending} onCancel={onClose} onOk={() => form.submit()} destroyOnHidden>
      {save.error ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message={errorText(save.error)} /> : null}
      <Form<BlocklistInput> form={form} layout="vertical" onFinish={(values) => save.mutate({ ...values, reason: values.reason ?? '' })}
        initialValues={entry ? { pattern: entry.pattern, match_type: entry.match_type, reason: entry.reason } : { match_type: 'root', reason: '' }}>
        <Form.Item name="pattern" label={t('blocklist.pattern')} rules={[{ required: true, whitespace: true, max: 253 }]}>
          <Input placeholder={t('blocklist.patternPlaceholder')} autoComplete="off" />
        </Form.Item>
        <Form.Item name="match_type" label={t('blocklist.matchType')}>
          <Radio.Group options={[{ value: 'root', label: t('blocklist.root') }, { value: 'exact', label: t('blocklist.exact') }]} />
        </Form.Item>
        <Form.Item name="reason" label={t('blocklist.reason')} rules={[{ max: 512 }]}><Input.TextArea rows={2} /></Form.Item>
      </Form>
    </Modal>
  )
}

function ImportModal({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [text, setText] = useState('')
  const run = useMutation({
    mutationFn: () => domainBlocklistApi.importText(token, text, newDomainTrustKey('blocklist-import')),
    onSuccess: (result) => {
      void message.success(t('blocklist.imported', result))
      void client.invalidateQueries({ queryKey: ['domainBlocklist'] })
      onClose()
    },
  })
  return (
    <Modal open title={t('blocklist.importTitle')} okText={t('blocklist.import')} cancelText={t('blocklist.cancel')}
      okButtonProps={{ disabled: text.trim() === '' }} confirmLoading={run.isPending} onCancel={onClose} onOk={() => run.mutate()}>
      <Typography.Paragraph type="secondary">{t('blocklist.importHint')}</Typography.Paragraph>
      {run.error ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message={errorText(run.error)} /> : null}
      <Input.TextArea rows={10} value={text} spellCheck={false} aria-label={t('blocklist.importTitle')}
        placeholder={t('blocklist.importPlaceholder')} onChange={(event) => setText(event.target.value)} />
    </Modal>
  )
}

function BlocklistTab() {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [search, setSearch] = useState('')
  const [editing, setEditing] = useState<{ entry: BlocklistEntry | null } | null>(null)
  const [importing, setImporting] = useState(false)
  const query = useQuery({ queryKey: ['domainBlocklist', search], queryFn: () => domainBlocklistApi.list(token, search), enabled: !!token })
  const remove = useMutation({
    mutationFn: (entry: BlocklistEntry) => domainBlocklistApi.remove(token, entry.id, entry.revision, newDomainTrustKey('blocklist-delete')),
    onSuccess: () => {
      void message.success(t('blocklist.deleted'))
      void client.invalidateQueries({ queryKey: ['domainBlocklist'] })
    },
    onError: (error) => { void feedback.error(errorText(error)) },
  })
  const exportCSV = async () => {
    try {
      const blob = await domainBlocklistApi.exportCSV(token)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'domain-blocklist.csv'
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      void feedback.error(errorText(error))
    }
  }
  return <>
    <Space wrap style={{ marginBottom: 12 }}>
      <Input.Search allowClear placeholder={t('blocklist.search')} aria-label={t('blocklist.search')} onSearch={setSearch} style={{ width: 240 }} />
      <Button type="primary" icon={<Plus size={14} />} onClick={() => setEditing({ entry: null })}>{t('blocklist.add')}</Button>
      <Button icon={<Upload size={14} />} onClick={() => setImporting(true)}>{t('blocklist.import')}</Button>
      <Button icon={<Download size={14} />} onClick={() => { void exportCSV() }}>{t('blocklist.export')}</Button>
    </Space>
    {query.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(query.error) })} /> : null}
    <Table<BlocklistEntry> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data ?? []} scroll={{ x: 760 }}
      columns={[
        { title: t('blocklist.pattern'), dataIndex: 'pattern' },
        { title: t('blocklist.matchType'), dataIndex: 'match_type', render: (value: string) => <Tag>{t(`blocklist.${value}`)}</Tag> },
        { title: t('blocklist.reason'), dataIndex: 'reason', ellipsis: true },
        { title: t('blocklist.updatedAt'), dataIndex: 'updated_at', render: date },
        { title: t('blocklist.actions'), key: 'actions', render: (_: unknown, entry) => <Space>
          <Button size="small" onClick={() => setEditing({ entry })}>{t('blocklist.edit')}</Button>
          <Popconfirm title={t('blocklist.deleteConfirm')} onConfirm={() => remove.mutate(entry)}>
            <Button size="small" danger>{t('blocklist.delete')}</Button>
          </Popconfirm>
        </Space> },
      ]} />
    {editing ? <EntryModal entry={editing.entry} onClose={() => setEditing(null)} /> : null}
    {importing ? <ImportModal onClose={() => setImporting(false)} /> : null}
  </>
}

function HitsTab() {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [selected, setSelected] = useState<string[]>([])
  const query = useQuery({ queryKey: ['domainBlocklistHits'], queryFn: () => domainBlocklistApi.hits(token), enabled: !!token })
  const disable = useMutation({
    mutationFn: (hits: BlocklistHit[]) => sitesApi.batchAction(token, {
      action: 'disable', items: hits.map((hit) => ({ id: hit.site_id, expected_version: hit.revision })),
    }, newDomainTrustKey('blocklist-disable')),
    onSuccess: (result) => {
      const failed = result.items.filter((item) => item.status === 'failed').length
      void message.success(t('hits.disabled_count', { count: result.items.length - failed }))
      if (failed > 0) void feedback.warning(t('hits.failed_count', { count: failed }))
      setSelected([])
      void client.invalidateQueries({ queryKey: ['domainBlocklistHits'] })
    },
    onError: (error) => { void feedback.error(errorText(error)) },
  })
  const hits = query.data ?? []
  const chosen = hits.filter((hit) => selected.includes(hit.site_id) && hit.enabled)
  return <>
    <Typography.Paragraph type="secondary">{t('hits.hint')}</Typography.Paragraph>
    <Button danger style={{ marginBottom: 12 }} disabled={chosen.length === 0 || chosen.length > 100} loading={disable.isPending}
      onClick={() => disable.mutate(chosen)}>{t('hits.disable')}</Button>
    {query.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(query.error) })} /> : null}
    <Table<BlocklistHit> rowKey="site_id" size="small" loading={query.isLoading} dataSource={hits} locale={{ emptyText: t('hits.none') }}
      rowSelection={{ selectedRowKeys: selected, onChange: (keys) => setSelected(keys as string[]),
        getCheckboxProps: (hit) => ({ disabled: !hit.enabled }) }}
      columns={[
        { title: t('hits.site'), dataIndex: 'display_id' },
        { title: t('hits.domain'), dataIndex: 'domain' },
        { title: t('hits.pattern'), dataIndex: 'pattern' },
        { title: t('hits.status'), dataIndex: 'enabled', render: (enabled: boolean) => <Tag color={enabled ? 'green' : 'default'}>{enabled ? t('hits.enabled') : t('hits.disabled')}</Tag> },
      ]} />
  </>
}

function OwnershipsTab() {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [apex, setApex] = useState('')
  const [status, setStatus] = useState<OwnershipStatus | ''>('')
  const query = useQuery({ queryKey: ['domainOwnershipsAdmin', apex, status], queryFn: () => domainBlocklistApi.ownerships(token, apex, status), enabled: !!token })
  const revoke = useMutation({
    mutationFn: (id: string) => domainBlocklistApi.revokeOwnership(token, id),
    onSuccess: () => {
      void message.success(t('ownership.revoked'))
      void client.invalidateQueries({ queryKey: ['domainOwnershipsAdmin'] })
    },
    onError: (error) => { void feedback.error(errorText(error)) },
  })
  return <>
    <Space wrap style={{ marginBottom: 12 }}>
      <Input.Search allowClear placeholder={t('ownership.apex')} aria-label={t('ownership.apex')} onSearch={setApex} style={{ width: 220 }} />
      <Select<OwnershipStatus | ''> value={status} onChange={setStatus} style={{ width: 160 }} aria-label={t('ownership.filterStatus')}
        options={[{ value: '', label: t('ownership.all') }, ...(['pending', 'verified', 'expired', 'revoked'] as const).map((value) => ({ value, label: t(`statuses.${value}`) }))]} />
    </Space>
    {query.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(query.error) })} /> : null}
    <Table<DomainOwnership> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data ?? []} scroll={{ x: 900 }}
      columns={[
        { title: t('ownership.apex'), dataIndex: 'apex' },
        { title: t('ownership.scope'), dataIndex: 'scope_id', ellipsis: true },
        { title: t('ownership.method'), dataIndex: 'method', render: (value: string) => t(`methods.${value}`) },
        { title: t('ownership.status'), dataIndex: 'status', render: (value: OwnershipStatus) => <Tag color={value === 'verified' ? 'green' : value === 'expired' ? 'orange' : 'default'}>{t(`statuses.${value}`)}</Tag> },
        { title: t('ownership.verifiedAt'), dataIndex: 'verified_at', render: date },
        { title: t('blocklist.actions'), key: 'actions', render: (_: unknown, item) => item.status === 'revoked' ? null
          : <Popconfirm title={t('ownership.revokeConfirm')} onConfirm={() => revoke.mutate(item.id)}><Button size="small" danger>{t('ownership.revoke')}</Button></Popconfirm> },
      ]} />
  </>
}

function SuspensionsTab() {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const errorText = useErrorText()
  const [includeReleased, setIncludeReleased] = useState(false)
  const query = useQuery({ queryKey: ['domainClaimSuspensions', includeReleased], queryFn: () => domainBlocklistApi.suspensions(token, includeReleased), enabled: !!token })
  const release = useMutation({
    mutationFn: (id: string) => domainBlocklistApi.release(token, id),
    onSuccess: () => {
      void message.success(t('suspension.released'))
      void client.invalidateQueries({ queryKey: ['domainClaimSuspensions'] })
    },
    onError: (error) => { void feedback.error(errorText(error)) },
  })
  return <>
    <Checkbox checked={includeReleased} onChange={(event) => setIncludeReleased(event.target.checked)} style={{ marginBottom: 12 }}>{t('suspension.includeReleased')}</Checkbox>
    {query.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(query.error) })} /> : null}
    <Table<ClaimSuspension> rowKey="id" size="small" loading={query.isLoading} dataSource={query.data ?? []} scroll={{ x: 900 }}
      columns={[
        { title: t('suspension.domain'), dataIndex: 'domain' },
        { title: t('suspension.site'), dataIndex: 'site_id', ellipsis: true },
        { title: t('suspension.claimant'), dataIndex: 'claimant_scope_id', ellipsis: true },
        { title: t('suspension.createdAt'), dataIndex: 'created_at', render: date },
        { title: t('suspension.releasedAt'), dataIndex: 'released_at', render: date },
        { title: t('suspension.reason'), dataIndex: 'release_reason', render: (value?: string) => value ? t(`suspension.${value}`, { defaultValue: value }) : '-' },
        { title: t('blocklist.actions'), key: 'actions', render: (_: unknown, item) => item.released_at ? null
          : <Popconfirm title={t('suspension.releaseConfirm')} onConfirm={() => release.mutate(item.id)}><Button size="small">{t('suspension.release')}</Button></Popconfirm> },
      ]} />
  </>
}

export default function DomainSecurityPage() {
  const { t } = useTranslation('domainTrust')
  const principal = useSessionStore((state) => state.principal)
  const allowed = principal?.scope_kind === 'platform' && (principal.permissions.includes(domainSecurityPermission) ||
    principal.permissions.includes('platform.admin'))
  if (!allowed) return <Result status="error" icon={<ShieldOff size={72} aria-hidden="true" />} title={t('errors.forbidden')} />
  return (
    <div className="page">
      <Typography.Title level={4}>{t('admin.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('admin.subtitle')}</Typography.Paragraph>
      <Tabs destroyOnHidden items={[
        { key: 'blocklist', label: t('admin.tabs.blocklist'), children: <BlocklistTab /> },
        { key: 'hits', label: t('admin.tabs.hits'), children: <HitsTab /> },
        { key: 'ownerships', label: t('admin.tabs.ownerships'), children: <OwnershipsTab /> },
        { key: 'suspensions', label: t('admin.tabs.suspensions'), children: <SuspensionsTab /> },
      ]} />
    </div>
  )
}
