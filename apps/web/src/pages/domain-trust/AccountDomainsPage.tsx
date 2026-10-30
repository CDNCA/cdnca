import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Input, Modal, Popconfirm, Table, Tag, Typography } from 'antd'
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError } from '../../api/auth'
import { domainOwnershipApi, type ClaimSuspension, type DomainOwnership, type OwnershipStatus } from '../../api/domainTrust'
import { useSessionStore } from '../../auth/session'
import '../../i18n/domainTrust'
import { DomainOwnershipPanel } from './DomainOwnershipPanel'
import { useFeedback, FeedbackWhen } from '@cdnca/ui'

function codeOf(error: unknown): string {
  return error instanceof ApiError ? error.code : 'request_failed'
}

function date(value?: string) {
  return value ? new Date(value).toLocaleString() : '-'
}

export default function AccountDomainsPage() {
  const { t } = useTranslation('domainTrust')
  const { message } = App.useApp()
  const feedback = useFeedback()
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const client = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [domain, setDomain] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  // The latest record per row after "立即检查", so the expanded panel shows its result.
  const [checked, setChecked] = useState<Record<string, DomainOwnership>>({})
  const list = useQuery({ queryKey: ['domainOwnerships'], queryFn: () => domainOwnershipApi.list(token), enabled: !!token })
  const suspensions = useQuery({ queryKey: ['domainClaimSuspensionsMine'], queryFn: () => domainOwnershipApi.suspensions(token), enabled: !!token })
  const revoke = useMutation({
    mutationFn: (apex: string) => domainOwnershipApi.revoke(token, apex),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['domainOwnerships'] }) },
    onError: (error) => { void feedback.error(t(`errors.${codeOf(error)}`, { defaultValue: t('errors.failed', { code: codeOf(error) }) })) },
  })
  const check = useMutation({
    mutationFn: (item: DomainOwnership) => domainOwnershipApi.check(token, item.apex),
    onSuccess: (value, item) => {
      setChecked((current) => ({ ...current, [item.id]: value }))
      setOpen(item.id)
      if (value.status === 'verified') void message.success(`${value.apex} · ${t('user.verified')}`)
      else {
        const code = value.last_failure_code || 'verification_failed'
        void feedback.warning(t('user.notYet', { reason: t(`user.failures.${code}`, { defaultValue: code }) }))
      }
      void client.invalidateQueries({ queryKey: ['domainOwnerships'] })
    },
    onError: (error) => { void feedback.error(t(`errors.${codeOf(error)}`, { defaultValue: t('errors.failed', { code: codeOf(error) }) })) },
  })
  const disabled = list.error instanceof ApiError && list.error.code === 'domain_ownership_disabled'
  return (
    <div className="page">
      <Typography.Title level={4}>{t('user.title')}</Typography.Title>
      <Typography.Paragraph type="secondary">{t('user.subtitle')}</Typography.Paragraph>
      {disabled ? <Alert type="info" showIcon message={t('errors.domain_ownership_disabled')} />
        : list.error ? <FeedbackWhen title={t('errors.load', { code: codeOf(list.error) })} /> : null}
      <Button type="primary" icon={<Plus size={14} />} style={{ marginBottom: 12 }} onClick={() => { setDomain(''); setAdding(true) }}>{t('user.add')}</Button>
      <Table<DomainOwnership> rowKey="id" size="small" loading={list.isLoading} dataSource={list.data ?? []} scroll={{ x: 760 }}
        expandable={{ expandedRowKeys: open ? [open] : [], showExpandColumn: false,
          expandedRowRender: (item) => {
            const current = checked[item.id] ?? item
            return <DomainOwnershipPanel key={current.revision} domain={item.apex} initial={current} />
          } }}
        columns={[
          { title: t('ownership.apex'), dataIndex: 'apex' },
          { title: t('ownership.method'), dataIndex: 'method', render: (value: string) => t(`methods.${value}`) },
          { title: t('ownership.status'), dataIndex: 'status', render: (value: OwnershipStatus) =>
            <Tag color={value === 'verified' ? 'green' : value === 'expired' ? 'orange' : 'default'}>{t(`statuses.${value}`)}</Tag> },
          { title: t('ownership.verifiedAt'), dataIndex: 'verified_at', render: date },
          { title: t('blocklist.actions'), key: 'actions', render: (_: unknown, item) => <>
            {item.status === 'verified' ? (
              <Button size="small" style={{ marginRight: 8 }} onClick={() => setOpen(open === item.id ? null : item.id)}>{t('user.conflicts')}</Button>
            ) : (
              <Button size="small" style={{ marginRight: 8 }} loading={check.isPending && check.variables?.id === item.id}
                onClick={() => check.mutate(item)}>{t('user.check')}</Button>
            )}
            <Popconfirm title={t('user.revokeConfirm')} onConfirm={() => revoke.mutate(item.apex)}>
              <Button size="small" danger>{t('user.revoke')}</Button>
            </Popconfirm>
          </> },
        ]} />
      {(suspensions.data?.length ?? 0) > 0 ? <>
        <Typography.Title level={5} style={{ marginTop: 24 }}>{t('user.suspensionsTitle')}</Typography.Title>
        <Alert type="warning" showIcon style={{ marginBottom: 12 }} message={t('user.suspensionsHint')} />
        <Table<ClaimSuspension> rowKey="id" size="small" pagination={false} dataSource={suspensions.data ?? []}
          columns={[
            { title: t('suspension.domain'), dataIndex: 'domain' },
            { title: t('suspension.site'), dataIndex: 'site_id', ellipsis: true },
            { title: t('suspension.createdAt'), dataIndex: 'created_at', render: date },
          ]} />
      </> : null}
      <Modal open={adding} title={t('user.add')} footer={null} onCancel={() => setAdding(false)} destroyOnHidden width={620}>
        <Input value={domain} placeholder={t('user.domainPlaceholder')} aria-label={t('user.domain')} style={{ marginBottom: 12 }}
          onChange={(event) => setDomain(event.target.value.trim())} />
        {domain.includes('.') ? <DomainOwnershipPanel key={domain} domain={domain} /> : null}
      </Modal>
    </div>
  )
}
