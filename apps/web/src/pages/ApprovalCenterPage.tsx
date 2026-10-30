import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App, Button, Descriptions, Drawer, Input, Select, Space, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { ApiError } from '../api/auth'
import {
  approvalCenterApi, approvalStates, createApprovalStepUp,
  type ApprovalRequest, type ApprovalState,
} from '../api/approvalCenter'
import { useSessionStore } from '../auth/session'
import { formatDateTime } from '../i18n/formatters'
import '../i18n/approvalCenter'

// 平台审批中心：列出待审单，审批人批准即用自己的会话执行，
// 绑定了 MFA 的审批人必须输入验证码。退款/作废、调余额只列入口跳原页面。
const stateColors: Record<ApprovalState, string> = {
  pending: 'processing', expired: 'default', rejected: 'default', executing: 'warning', unknown: 'warning', executed: 'success', failed: 'error',
}

const targetPaths: Record<string, string> = {
  'site.batch_delete': '/site/list', 'cache.whole_site_purge': '/site/cache-clean', 'firewall.policy': '/config/firewall-action',
  'control.upgrade': '/sys/op', 'site.batch_disable': '/site/list', 'node.batch_disable': '/node/list',
  'stream.batch_delete': '/stream/list', 'user.delete': '/sys/user',
}

export default function ApprovalCenterPage() {
  const { t } = useTranslation('approvalCenter')
  const token = useSessionStore((state) => state.accessToken) ?? ''
  const permissions = useSessionStore((state) => state.principal?.permissions ?? [])
  const canApprove = permissions.includes('approvals.approve')
  const [state, setState] = useState<ApprovalState | undefined>('pending')
  const [openID, setOpenID] = useState<string | null>(null)
  const list = useQuery({ queryKey: ['approval-center', 'list', state], queryFn: () => approvalCenterApi.list(token, state), enabled: Boolean(token) })

  const columns: TableColumnsType<ApprovalRequest> = [
    { title: t('columns.rule'), dataIndex: 'rule', render: (rule: string) => <Space>{t(`rules.${rule}`, { defaultValue: rule })}<Link to={targetPaths[rule] ?? '/'}>{t('actions.open')}</Link></Space> },
    { title: t('columns.reason'), dataIndex: 'reason', ellipsis: true },
    { title: t('columns.requester'), dataIndex: 'requested_by_name' },
    { title: t('columns.requestedAt'), dataIndex: 'requested_at', render: (value: string) => formatDateTime(value) },
    { title: t('columns.expiresAt'), dataIndex: 'expires_at', render: (value: string) => formatDateTime(value) },
    { title: t('columns.state'), dataIndex: 'state', render: (value: ApprovalState) => <Tag color={stateColors[value]}>{t(`states.${value}`)}</Tag> },
    { title: t('columns.actions'), key: 'actions', render: (_, item) => <Button type="link" onClick={() => setOpenID(item.id)}>{t('actions.view')}</Button> },
  ]

  return (
    <div data-testid="approval-center-page" style={{ minWidth: 0 }}>
      <Typography.Title level={4}>{t('title')}</Typography.Title>
      <Space style={{ marginBottom: 12 }}>
        <Select aria-label={t('columns.state')} style={{ width: 180 }} value={state ?? 'all'} onChange={(value) => setState(value === 'all' ? undefined : value as ApprovalState)}
          options={[{ value: 'all', label: t('filters.all') }, ...approvalStates.map((value) => ({ value, label: t(`states.${value}`) }))]} />
        <Button icon={<RefreshCw size={14} />} onClick={() => void list.refetch()}>{t('actions.refresh')}</Button>
      </Space>
      {list.error ? <Alert type="error" showIcon message={errorText(t, list.error)} /> : null}
      <Table rowKey="id" size="small" loading={list.isPending} columns={columns} dataSource={list.data ?? []} pagination={false} locale={{ emptyText: t('empty') }} />
      {openID ? <ApprovalDrawer id={openID} token={token} canApprove={canApprove} onClose={() => setOpenID(null)} /> : null}
    </div>
  )
}

function errorText(t: (key: string) => string, error: unknown): string {
  const code = error instanceof ApiError ? error.code : 'unknown'
  const text = t(`errors.${code}`)
  return text === `errors.${code}` ? t('errors.unknown') : text
}

function ApprovalDrawer({ id, token, canApprove, onClose }: { id: string; token: string; canApprove: boolean; onClose: () => void }) {
  const { t } = useTranslation('approvalCenter')
  const { message } = App.useApp()
  const queryClient = useQueryClient()
  const [note, setNote] = useState('')
  const [code, setCode] = useState('')
  const detail = useQuery({ queryKey: ['approval-center', 'detail', id], queryFn: () => approvalCenterApi.get(token, id) })
  const decide = useMutation({
    mutationFn: async (decision: 'approve' | 'reject') => {
      const current = detail.data!
      const stepUpToken = decision === 'approve' && current.stepUpRequired ? await createApprovalStepUp(token, code) : undefined
      return approvalCenterApi.decide(token, id, decision, { expected_revision: current.approval.revision, note, ...(stepUpToken ? { step_up_token: stepUpToken } : {}) })
    },
    onSuccess: (result) => {
      void message.success(t(`states.${result.state}`))
      void queryClient.invalidateQueries({ queryKey: ['approval-center'] })
    },
  })
  const item = detail.data?.approval
  const pending = item?.state === 'pending'
  return (
    <Drawer open width={640} title={t('detail.title')} onClose={onClose} destroyOnHidden>
      {detail.error ? <Alert type="error" showIcon message={errorText(t, detail.error)} /> : null}
      {item ? <Space direction="vertical" style={{ width: '100%' }}>
        <Descriptions size="small" column={1} bordered items={[
          { key: 'rule', label: t('columns.rule'), children: t(`rules.${item.rule}`, { defaultValue: item.rule }) },
          { key: 'state', label: t('columns.state'), children: <Tag color={stateColors[item.state]}>{t(`states.${item.state}`)}</Tag> },
          { key: 'reason', label: t('columns.reason'), children: item.reason },
          { key: 'requester', label: t('columns.requester'), children: item.requested_by_name },
          { key: 'requestedAt', label: t('columns.requestedAt'), children: formatDateTime(item.requested_at) },
          { key: 'expiresAt', label: t('columns.expiresAt'), children: formatDateTime(item.expires_at) },
          ...(item.decided_at ? [
            { key: 'decider', label: t('detail.decider'), children: <Space>{item.decided_by_name}{item.self_approved ? <Tag>{t('detail.selfApproved')}</Tag> : null}</Space> },
            { key: 'decidedAt', label: t('detail.decidedAt'), children: formatDateTime(item.decided_at) },
            { key: 'note', label: t('detail.note'), children: item.decision_note || '-' },
          ] : []),
          ...(item.step_up ? [{ key: 'stepUp', label: t('detail.stepUp'), children: item.step_up === 'mfa' ? t('detail.stepUpMfa') : t('detail.stepUpNone') }] : []),
        ]} />
        {item.state === 'unknown' ? <Alert type="warning" showIcon message={t('detail.unknownTitle')}
          description={<Space direction="vertical" size={4}><span>{t('detail.unknownHint')}</span><Link to={targetPaths[item.rule] ?? '/'}>{t('actions.open')}</Link></Space>} /> : null}
        <Typography.Text strong>{t('detail.steps', { count: item.step_count })}</Typography.Text>
        {item.steps.map((step, index) => <pre key={index} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, fontSize: 12 }}>
          {`${step.method} ${step.path}${step.query ? `?${step.query}` : ''}${step.body ? `\n${step.body}` : ''}`}
          {item.results?.[index] ? `\n→ ${item.results[index].status} ${item.results[index].body}` : ''}
        </pre>)}
        {pending && canApprove ? <Space direction="vertical" style={{ width: '100%' }}>
          <Input.TextArea aria-label={t('detail.note')} placeholder={t('detail.notePlaceholder')} maxLength={500} value={note} onChange={(event) => setNote(event.target.value)} />
          {detail.data?.stepUpRequired ? <>
            <Typography.Text type="secondary">{t('detail.codeHint')}</Typography.Text>
            <Input aria-label={t('detail.codeLabel')} placeholder={t('detail.codeLabel')} inputMode="numeric" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))} style={{ width: 160 }} />
          </> : null}
          {decide.error ? <Alert type="error" showIcon message={errorText(t, decide.error)} /> : null}
          <Space>
            <Button type="primary" danger loading={decide.isPending && decide.variables === 'approve'} disabled={decide.isPending || (detail.data?.stepUpRequired && code.length !== 6)} onClick={() => decide.mutate('approve')}>{t('actions.approve')}</Button>
            <Button loading={decide.isPending && decide.variables === 'reject'} disabled={decide.isPending} onClick={() => decide.mutate('reject')}>{t('actions.reject')}</Button>
          </Space>
        </Space> : null}
      </Space> : null}
    </Drawer>
  )
}
