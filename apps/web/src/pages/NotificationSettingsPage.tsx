import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Checkbox, Drawer, Form, Input, InputNumber, Modal, Radio, Result, Space, Spin, Table, Tag, Typography, type TableColumnsType } from 'antd'
import { ChevronDown, ChevronLeft, ChevronRight, ListChecks, Plus, RefreshCw, Save } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, type Principal } from '../api/auth'
import {
	  newNotificationRequestKey,
	  notificationsApi,
  type NotificationChannels,
  type NotificationDeliveryAttempt,
  type NotificationDeliveryLog,
  type NotificationSubscription,
  type NotificationTemplate,
  type SubscriptionWrite,
  type SwitchWrite,
  type TemplateWrite,
} from '../api/notifications'
import { useSessionStore } from '../auth/session'
import { notificationTemplateName, notificationVariableName } from '../i18n/notificationTemplateNames'
import NotificationDeliveryPolicyPanel from './NotificationDeliveryPolicyPanel'
import type { EventSubscriptionRow } from './tickets/useEventSubscriptionRows'
import { FeedbackWhen, OutcomeUnknown, fieldReasonText, useFormSubmitError, type FormErrorMap, type SubmitFieldError } from '@cdnca/ui'

type Mode = 'admin' | 'account'
type AccountOwner = readonly ['tenant', string, string, string, number]
type PendingAccountWrite = { value: SwitchWrite; revision: number; requestKey: string }
type ChannelAttempt = { kind: 'channels'; value: SwitchWrite; revision: number; requestKey: string }
type TemplateForm = Omit<TemplateWrite, 'variables'> & { template_id: string; version: number; channel: 'email' | 'sms'; variables_text: string }
type TemplateAttempt = { kind: 'template'; templateId: string; version: number; channel: 'email' | 'sms'; value: TemplateWrite; requestKey: string }
type PendingAdminWrite = ChannelAttempt | TemplateAttempt
type WriteKind = 'account' | 'channels' | 'template'
type TemplateCreationResult = Promise<{ error?: unknown }>

const utf8Encoder = new TextEncoder()
// A refused template field lands on its box; variables[n]
// (server limit 32) all go to the one comma-separated variables box.
const templateErrorMap: FormErrorMap = {
  variables: 'variables_text',
  ...Object.fromEntries(Array.from({ length: 32 }, (_, index) => [`variables[${index}]`, 'variables_text'])),
}
const accountEventType = 'announcement.published' as const

function accountOwner(principal: Principal, sessionEpoch: number): AccountOwner | null {
  if (!principal.scope_id || !principal.user_id || sessionEpoch < 1) return null
  // 平台管理员没有独立租户，此页展示管理员自己的订阅开关，所以平台作用域按自身作用域处理。
  if (principal.scope_kind === 'tenant') {
    if (!principal.tenant_id) return null
  } else if (principal.scope_kind !== 'platform' || principal.tenant_id !== null) {
    return null
  }
  return ['tenant', principal.scope_id, principal.scope_id, principal.user_id, sessionEpoch]
}

function accountQueryKey(owner: AccountOwner) {
  return ['notification-subscription', ...owner, accountEventType] as const
}

function accountMutationKey(owner: AccountOwner) {
  return ['notification-subscription-write', ...owner, accountEventType] as const
}

export default function NotificationSettingsPage({ mode, embedded = false, eventRows = [], extraEventRows = [], grouped = false, eventError }: {
  mode: Mode
  embedded?: boolean
  // tp-b7：消息订阅页把套餐/证书/工单事件作为同一张表的后续行（账户模式）。
  eventRows?: EventSubscriptionRow[]
  // grouped 时 eventRows 是 6 个主消息类型，公告与 extraEventRows 进"更多消息类型"折叠区。
  extraEventRows?: EventSubscriptionRow[]
  grouped?: boolean
  eventError?: unknown
}) {
  const { t } = useTranslation(mode === 'admin' ? 'notificationSettings' : 'accountSubscriptions')
  const accessToken = useSessionStore((state) => state.accessToken)
  const principal = useSessionStore((state) => state.principal)
  const sessionEpoch = useSessionStore((state) => state.sessionEpoch)

  if (!accessToken || !principal) return null

  const owner = mode === 'account' ? accountOwner(principal, sessionEpoch) : null
  const canRead = mode === 'account'
    ? owner !== null
    : principal.scope_kind === 'platform' && principal.permissions.includes('system_configuration.read')
  if (!canRead) {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }

  return (
    <NotificationSettingsPageContent
      key={`${mode}:${principal.scope_id}:${sessionEpoch}`}
      accessToken={accessToken}
      principal={principal}
      scopeID={principal.scope_id}
      sessionEpoch={sessionEpoch}
      accountOwner={owner}
      mode={mode}
      embedded={embedded}
      eventRows={eventRows}
      extraEventRows={extraEventRows}
      grouped={grouped}
      eventError={eventError}
    />
  )
}

function NotificationSettingsPageContent({ accessToken, principal, scopeID, sessionEpoch, accountOwner, mode, embedded, eventRows, extraEventRows, grouped, eventError }: {
  accessToken: string
  principal: Principal
  scopeID: string
  sessionEpoch: number
  accountOwner: AccountOwner | null
  mode: Mode
  embedded: boolean
  eventRows: EventSubscriptionRow[]
  extraEventRows: EventSubscriptionRow[]
  grouped: boolean
  eventError: unknown
}) {
  const { t } = useTranslation(mode === 'admin' ? 'notificationSettings' : 'accountSubscriptions')
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const queryClient = useQueryClient()
  const canManage = principal.permissions.includes('system_configuration.manage')
  const [accountPending, setAccountPending] = useState<PendingAccountWrite | null>(null)
  const [adminPending, setAdminPending] = useState<PendingAdminWrite | null>(null)
  const [writeError, setWriteError] = useState<ApiError | null>(null)
  const [writeErrorKind, setWriteErrorKind] = useState<WriteKind | null>(null)
  const [adminDraftVersion, setAdminDraftVersion] = useState(0)

  const scopedAccountQueryKey = accountOwner
    ? accountQueryKey(accountOwner)
    : ['notification-subscription', scopeID, sessionEpoch, accountEventType] as const
  const scopedAccountMutationKey = accountOwner
    ? accountMutationKey(accountOwner)
    : ['notification-subscription-write', scopeID, sessionEpoch, accountEventType] as const
  const adminQueryKey = ['notification-settings', scopeID, sessionEpoch] as const
  const adminChannelMutationKey = ['notification-settings-channels-write', scopeID, sessionEpoch] as const
  const adminTemplateMutationKey = ['notification-settings-template-write', scopeID, sessionEpoch] as const
  const accountQuery = useQuery({
    queryKey: scopedAccountQueryKey,
    queryFn: () => notificationsApi.getSubscription(accessTokenRef.current, accountEventType),
    enabled: mode === 'account',
  })
  const adminQuery = useQuery({
    queryKey: adminQueryKey,
    queryFn: async () => {
      const [channels, templates, health] = await Promise.all([
        notificationsApi.getChannels(accessTokenRef.current),
        notificationsApi.listTemplates(accessTokenRef.current),
        notificationsApi.getRuntimeHealth(accessTokenRef.current),
      ])
      return { channels, templates, health }
    },
    enabled: mode === 'admin',
  })

  const accountMutation = useMutation({
	    gcTime: 0,
	    mutationKey: scopedAccountMutationKey,
	    mutationFn: (attempt: PendingAccountWrite) => notificationsApi.putSubscription(
	      accessTokenRef.current, accountEventType, attempt.value, attempt.revision, attempt.requestKey,
	    ),
    onSuccess: (value) => {
      setAccountPending(null)
      setWriteError(null)
      setWriteErrorKind(null)
      queryClient.setQueryData(scopedAccountQueryKey, value)
    },
    onError: (error: ApiError, attempt) => {
      setAccountPending(isDeterministicWriteError(error) ? null : attempt)
      setWriteError(error)
      setWriteErrorKind('account')
    },
  })
	  const adminMutation = useMutation({
	    gcTime: 0,
	    mutationKey: adminChannelMutationKey,
	    mutationFn: (attempt: ChannelAttempt) =>
	      notificationsApi.putChannels(accessTokenRef.current, attempt.value, attempt.revision, attempt.requestKey),
    onSuccess: () => {
      setAdminPending(null)
      setWriteError(null)
      setWriteErrorKind(null)
      queryClient.invalidateQueries({ queryKey: adminQueryKey })
    },
    onError: (error: ApiError, attempt) => {
      setAdminPending(isDeterministicWriteError(error) ? null : attempt)
      setWriteError(error)
      setWriteErrorKind('channels')
    },
  })
  const templateMutation = useMutation({
	    gcTime: 0,
	    mutationKey: adminTemplateMutationKey,
	              mutationFn: (attempt: TemplateAttempt) => notificationsApi.putTemplate(
	      accessTokenRef.current, attempt.templateId, attempt.version, attempt.channel, attempt.value, attempt.requestKey,
	    ),
    onSuccess: () => {
      setAdminPending(null)
      setWriteError(null)
      setWriteErrorKind(null)
      queryClient.invalidateQueries({ queryKey: adminQueryKey })
    },
    onError: (error: ApiError, attempt) => {
      setAdminPending(isDeterministicWriteError(error) ? null : attempt)
      setWriteError(error)
      setWriteErrorKind('template')
    },
  })

  const removeMutations = (mutationKey: readonly unknown[]) => {
    const mutationCache = queryClient.getMutationCache()
    for (const mutation of mutationCache.findAll({ mutationKey, exact: true })) mutationCache.remove(mutation)
  }
  const abandonAccountWrite = () => {
    setAccountPending(null)
    setWriteError(null)
    setWriteErrorKind(null)
    accountMutation.reset()
    removeMutations(scopedAccountMutationKey)
    void accountQuery.refetch()
  }
  const abandonAdminWrite = () => {
    setAdminPending(null)
    setWriteError(null)
    setWriteErrorKind(null)
    adminMutation.reset()
    templateMutation.reset()
    removeMutations(adminChannelMutationKey)
    removeMutations(adminTemplateMutationKey)
    setAdminDraftVersion((version) => version + 1)
    void adminQuery.refetch()
  }

  const query = mode === 'admin' ? adminQuery : accountQuery
  if (query.isLoading) {
    return <div className="route-loading" aria-label={t('loading')}><Spin size="small" /></div>
  }
  if (query.error) {
    return errorResult(query.error as ApiError, t, () => { void query.refetch() })
  }

  return (
    <section className={embedded ? undefined : 'identity-page'} data-testid="notification-settings-page" data-embedded={embedded ? 'true' : undefined} style={{ minWidth: 0 }}>
      <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
        {!embedded && mode === 'admin' ? <Typography.Title level={3}>{t('title')}</Typography.Title> : null}
        {writeError && (accountPending || adminPending?.kind === 'channels') ? (
          <OutcomeUnknown title={t('uncertainty.title')} detail={t('uncertainty.description')} action={<Space wrap>
              <Button icon={<RefreshCw size={14} />} onClick={() => {
                if (accountPending) accountMutation.mutate(accountPending)
                else if (adminPending?.kind === 'channels') adminMutation.mutate(adminPending)
              }}>{t('actions.retrySame')}</Button>
              <Button onClick={accountPending ? abandonAccountWrite : abandonAdminWrite}>{t('actions.closeAndRefresh')}</Button>
            </Space>} />
        ) : null}
        {writeError && !accountPending && !adminPending && writeErrorKind !== 'template' ? <FeedbackWhen title={errorText(writeError, t)} /> : null}
        {mode === 'account' ? (
          <AccountSettings
            value={accountQuery.data!}
            eventRows={eventRows}
            extraEventRows={extraEventRows}
            grouped={grouped}
            eventError={eventError}
            disabled={accountMutation.isPending || accountPending !== null}
            onChange={(value) => {
	              const attempt = {
	                value,
	                revision: accountQuery.data!.revision,
	                requestKey: newNotificationRequestKey(),
              }
              setWriteError(null)
              setWriteErrorKind(null)
              accountMutation.mutate(attempt)
            }}
            t={t}
          />
        ) : (
          <>
            <NotificationDeliveryPolicyPanel />
            <AdminSettings
              key={adminDraftVersion}
              accessToken={accessTokenRef.current}
              scopeID={scopeID}
              sessionEpoch={sessionEpoch}
              channels={adminQuery.data!.channels}
              templates={adminQuery.data!.templates.items}
              ready={adminQuery.data!.health.ready && adminQuery.data!.health.worker_running}
              canManage={canManage}
              saving={adminMutation.isPending}
              locked={adminPending !== null}
              onSave={(value) => {
                setWriteError(null)
                setWriteErrorKind(null)
                adminMutation.mutate({
                  kind: 'channels', value, revision: adminQuery.data!.channels.revision,
                  requestKey: newNotificationRequestKey(),
                })
              }}
              templateSaving={templateMutation.isPending}
              templateError={writeErrorKind === 'template' && !adminPending ? writeError : null}
              pendingTemplate={adminPending?.kind === 'template' ? adminPending : null}
              onRetryTemplate={() => {
                if (adminPending?.kind === 'template') templateMutation.mutate(adminPending)
              }}
              onAbandonTemplate={abandonAdminWrite}
              onCreateTemplate={async (attempt) => {
                setWriteError(null)
                setWriteErrorKind(null)
                try {
                  await templateMutation.mutateAsync(attempt)
                  return {}
                } catch (error) {
                  return { error }
                }
              }}
              t={t}
            />
          </>
        )}
      </Space>
    </section>
  )
}

type AccountRow = { key: string; label: string; hint?: string; value: SwitchWrite & { sms_supported: boolean; email_supported: boolean; inbox_enabled?: boolean }; disabled: boolean; onChange: (value: SubscriptionWrite) => void; notice?: string; retry?: { label: string; run: () => void } }

// tp-b7：消息订阅是一张表——每行一个提醒项，列是手机提醒 / 邮件提醒两个开关，切换即自动保存。
// 租户（grouped）主表只有 6 个主消息类型；公告与我方另有的类型放在表下方
// "更多消息类型"折叠区（默认收起），列相同。平台工单成员照旧一张表：公告 + 工单事件。
function AccountSettings({ value, eventRows, extraEventRows, grouped, eventError, disabled, onChange, t }: {
  value: NotificationSubscription
  eventRows: EventSubscriptionRow[]
  extraEventRows: EventSubscriptionRow[]
  grouped: boolean
  eventError: unknown
  disabled: boolean
  onChange: (value: SwitchWrite) => void
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const [moreOpen, setMoreOpen] = useState(false)
  const announcement: AccountRow = { key: value.event_type, label: t('events.announcementPublished'), hint: t('hints.announcementPublished'), value, disabled, onChange }
  const mainRows: AccountRow[] = grouped ? eventRows : [announcement, ...eventRows]
  const moreRows: AccountRow[] = grouped ? [announcement, ...extraEventRows] : []
  const rows = [...mainRows, ...moreRows]
  // A channel the platform has not switched on and configured is not shown at all.
  const smsColumn = rows.some((row) => row.value.sms_supported)
  const emailColumn = rows.some((row) => row.value.email_supported)
  // 工单事件多一个站内信开关；其它事件这一格为空。写入总是带上当前站内信值，不会被短信/邮件切换覆盖。
  const inboxColumn = (list: AccountRow[]) => list.some((row) => row.value.inbox_enabled !== undefined)
  const channelSwitch = (channel: 'sms' | 'email' | 'inbox') => (_: unknown, row: AccountRow) => {
    const supported = channel === 'sms' ? row.value.sms_supported : channel === 'email' ? row.value.email_supported
      : row.value.inbox_enabled !== undefined
    if (!supported) return null
    const checked = channel === 'sms' ? row.value.sms_enabled : channel === 'email' ? row.value.email_enabled
      : row.value.inbox_enabled === true
    // 用勾选框；读屏名称仍为"类型 + 渠道"。
    return <Checkbox
      aria-label={`${row.label} ${t(`columns.${channel}`)}`}
      checked={checked}
      disabled={row.disabled}
      onChange={({ target: { checked: next } }) => row.onChange({
        sms_enabled: channel === 'sms' ? next : row.value.sms_enabled,
        email_enabled: channel === 'email' ? next : row.value.email_enabled,
        ...(row.value.inbox_enabled === undefined ? {} : { inbox_enabled: channel === 'inbox' ? next : row.value.inbox_enabled }),
      })}
    />
  }
  const columnsFor = (list: AccountRow[]): TableColumnsType<AccountRow> => {
    const columns: TableColumnsType<AccountRow> = [
      { title: t('columns.type'), key: 'type', render: (_: unknown, row) => <div className="account-subscription-item">
        <span className="account-subscription-item-label">{row.label}</span>
        {row.hint ? <span className="account-subscription-item-hint">{row.hint}</span> : null}
        {row.notice ? <span className="account-subscription-item-hint" role={row.retry ? 'alert' : 'status'}>
          {row.notice}
          {row.retry ? <Button type="link" size="small" aria-label={`${row.label} ${row.retry.label}`} onClick={row.retry.run}>{row.retry.label}</Button> : null}
        </span> : null}
      </div> },
    ]
    if (smsColumn) columns.push({ title: t('columns.sms'), key: 'sms', width: 136, align: 'center', render: channelSwitch('sms') })
    if (emailColumn) columns.push({ title: t('columns.email'), key: 'email', width: 136, align: 'center', render: channelSwitch('email') })
    if (inboxColumn(list)) columns.push({ title: t('columns.inbox'), key: 'inbox', width: 136, align: 'center', render: channelSwitch('inbox') })
    return columns
  }
  // 计数胶囊按主表（提醒项）统计。
  const count = (channel: 'sms' | 'email') => mainRows.filter((row) => channel === 'sms'
    ? row.value.sms_supported && row.value.sms_enabled
    : row.value.email_supported && row.value.email_enabled).length
  const table = (list: AccountRow[], label?: string) => (
    <div className="identity-table-scroll account-subscriptions-table" style={{ minWidth: 0 }}>
      <Table<AccountRow>
        rowKey="key"
        size="small"
        pagination={false}
        dataSource={list}
        scroll={{ x: 520 }}
        columns={columnsFor(list)}
        aria-label={label}
      />
    </div>
  )
  return (
    <section className="account-subscriptions-card" aria-labelledby="account-subscriptions-title">
      <header className="account-subscriptions-header">
        <div className="account-subscriptions-heading">
          <h1 id="account-subscriptions-title">{t('title')}</h1>
          <p>{t('subtitle')}</p>
        </div>
        {smsColumn || emailColumn ? <div className="account-subscriptions-stats">
          <span>{t('stats.items')} <strong>{mainRows.length}</strong></span>
          {smsColumn ? <span>{t('stats.sms')} <strong>{count('sms')}</strong></span> : null}
          {emailColumn ? <span>{t('stats.email')} <strong>{count('email')}</strong></span> : null}
        </div> : null}
      </header>
      {eventError ? <FeedbackWhen title={t('errors.eventsFailed', { code: eventError instanceof ApiError ? eventError.code : 'request_failed' })} /> : null}
      {!smsColumn && !emailColumn ? (
        <Typography.Text type="secondary">{t('values.noChannel')}</Typography.Text>
      ) : (
        <>
          {table(mainRows)}
          {moreRows.length ? <div className="account-subscriptions-more">
            <Button
              type="link"
              className="account-subscriptions-more-toggle"
              aria-expanded={moreOpen}
              aria-controls="account-subscriptions-more"
              icon={moreOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
              onClick={() => setMoreOpen((open) => !open)}
            >{t('more.toggle', { count: moreRows.length })}</Button>
            <div id="account-subscriptions-more" hidden={!moreOpen}>{moreOpen ? table(moreRows, t('more.title')) : null}</div>
          </div> : null}
        </>
      )}
    </section>
  )
}

function AdminSettings({ accessToken, scopeID, sessionEpoch, channels, templates, ready, canManage, saving, locked, onSave, templateSaving, templateError, pendingTemplate, onRetryTemplate, onAbandonTemplate, onCreateTemplate, t }: {
  accessToken: string
  scopeID: string
  sessionEpoch: number
  channels: NotificationChannels
  templates: NotificationTemplate[]
  ready: boolean
  canManage: boolean
  saving: boolean
  locked: boolean
  onSave: (value: SwitchWrite) => void
  templateSaving: boolean
  templateError: ApiError | null
  pendingTemplate: TemplateAttempt | null
  onRetryTemplate: () => void
  onAbandonTemplate: () => void
  onCreateTemplate: (attempt: TemplateAttempt) => TemplateCreationResult
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const [emailEnabled, setEmailEnabled] = useState(channels.email_enabled)
  const [smsEnabled, setSMSEnabled] = useState(channels.sms_enabled)
  const [templateOpen, setTemplateOpen] = useState(false)
  const { i18n } = useTranslation()
  const localized = i18n.resolvedLanguage !== 'en-US'
  const [deliveryOpen, setDeliveryOpen] = useState(false)
  const [form] = Form.useForm<TemplateForm>()
  const templateChannel = Form.useWatch('channel', form) ?? 'email'
  // The last submitted variables, to name a refused variables[n] by its value.
  const submittedVariables = useRef<string[]>([])
  // The refusal marked on the form: it is not repeated in the error bar.
  const [markedError, setMarkedError] = useState<unknown>(null)
  const markSubmitError = useFormSubmitError(form, templateErrorMap, { message: ({ field, reason }: SubmitFieldError) => {
    const match = /^variables\[(\d+)\]$/.exec(field)
    const value = match ? submittedVariables.current[Number(match[1])] : undefined
    const locale = i18n.resolvedLanguage === 'en-US' ? 'en' : i18n.resolvedLanguage === 'zh-TW' ? 'zh-tw' : 'zh-cn'
    return value === undefined ? undefined : `${value}：${fieldReasonText(reason, locale)}`
  } })
  useEffect(() => setEmailEnabled(channels.email_enabled), [channels.email_enabled])
  useEffect(() => setSMSEnabled(channels.sms_enabled), [channels.sms_enabled])
  return (
    <>
      <section className="notification-settings-channels-card" aria-label={t('sections.channels')}>
        <Typography.Title level={5}>{t('sections.channels')}</Typography.Title>
        <Space wrap>
          <Checkbox checked={smsEnabled} disabled={!channels.sms_supported || !canManage || saving || locked} onChange={(event) => setSMSEnabled(event.target.checked)}>{t('channels.sms')}</Checkbox>
          {!channels.sms_supported ? <Typography.Text type="secondary">{t('values.unsupported')}</Typography.Text> : null}
          <Checkbox checked={emailEnabled} disabled={!channels.email_supported || !canManage || saving || locked} onChange={(event) => setEmailEnabled(event.target.checked)}>{t('channels.email')}</Checkbox>
          {!channels.email_supported ? <Typography.Text type="secondary">{t('values.unsupported')}</Typography.Text> : null}
          <Tag color={ready ? 'success' : 'default'}>{ready ? t('health.ready') : t('health.notReady')}</Tag>
          <Button icon={<Save size={14} />} disabled={!canManage || locked || (smsEnabled === channels.sms_enabled && emailEnabled === channels.email_enabled)} loading={saving} onClick={() => onSave({ sms_enabled: smsEnabled, email_enabled: emailEnabled })}>{t('actions.save')}</Button>
          <Button icon={<Plus size={14} />} disabled={!canManage || locked} onClick={() => setTemplateOpen(true)}>{t('actions.newTemplate')}</Button>
          <Button icon={<ListChecks size={14} />} onClick={() => setDeliveryOpen(true)}>{t('deliveries.actions.open')}</Button>
        </Space>
      </section>
      <section className="notification-settings-policy-card" aria-label={t('sections.templates')}>
        <Typography.Title level={5}>{t('sections.templates')}</Typography.Title>
        <Table
          rowKey={(item) => `${item.template_id}:${item.version}:${item.channel}`}
          size="small"
          pagination={false}
          dataSource={templates}
          locale={{ emptyText: t('values.emptyTemplates') }}
          scroll={{ x: 720 }}
          columns={[
            { title: t('templates.name'), key: 'name', render: (_: unknown, item) => (localized && notificationTemplateName(item.template_id)) || '—' },
            { title: t('templates.id'), dataIndex: 'template_id' },
            { title: t('templates.version'), dataIndex: 'version', width: 90 },
            { title: t('templates.channel'), dataIndex: 'channel', width: 100, render: (channel: NotificationTemplate['channel']) => t(`channels.${channel}`) },
            { title: t('templates.variables'), dataIndex: 'variables', render: (variables: string[]) => variables.map((v) => localized ? notificationVariableName(v) : v).join('、') },
          ] satisfies TableColumnsType<NotificationTemplate>}
        />
      </section>
      <Modal
        open={templateOpen}
        title={t('form.title')}
        footer={null}
        destroyOnHidden
        onCancel={() => {
          if (!templateSaving && !locked) setTemplateOpen(false)
        }}
      >
        {pendingTemplate ? (
          <Alert
            type="warning"
            showIcon
            message={t('uncertainty.title')}
            description={t('uncertainty.description')}
            action={<Space wrap>
              <Button icon={<RefreshCw size={14} />} onClick={onRetryTemplate}>{t('actions.retrySame')}</Button>
              <Button onClick={onAbandonTemplate}>{t('actions.closeAndRefresh')}</Button>
            </Space>}
            style={{ marginBottom: 16 }}
          />
        ) : templateError && templateError !== markedError ? <Alert type="error" showIcon message={errorText(templateError, t)} style={{ marginBottom: 16 }} /> : null}
        <Form<TemplateForm>
          form={form}
          name="notification-template-create"
          layout="vertical"
          disabled={locked}
          initialValues={{ version: 1, channel: 'email', variables_text: '' }}
          onFinish={async (value) => {
            const variables = value.variables_text.split(',').map((item) => item.trim()).filter(Boolean)
            submittedVariables.current = variables
            setMarkedError(null)
            const { error } = await onCreateTemplate({
              kind: 'template',
              templateId: value.template_id,
	              version: value.version,
	              channel: value.channel,
	              requestKey: newNotificationRequestKey(),
	              value: {
                subject: value.channel === 'sms' ? '' : value.subject,
                body: value.body,
                variables,
              },
            })
            if (error !== undefined) {
              if (markSubmitError(error)) setMarkedError(error)
            } else {
              form.resetFields()
              setTemplateOpen(false)
            }
          }}
        >
          <Form.Item name="template_id" label={t('templates.id')} rules={[
            { required: true, message: t('validation.required') },
            { pattern: /^[a-z][a-z0-9._-]{0,95}$/, message: t('validation.templateId') },
          ]}>
            <Input maxLength={96} />
          </Form.Item>
          <Form.Item name="version" label={t('templates.version')} rules={[{ required: true, type: 'integer', min: 1, message: t('validation.version') }]}>
            <InputNumber min={1} precision={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="channel" label={t('form.channel')}>
            <Radio.Group>
              <Radio value="email">{t('channels.email')}</Radio>
              <Radio value="sms">{t('channels.sms')}</Radio>
            </Radio.Group>
          </Form.Item>
          {templateChannel === 'email' ? (
            <Form.Item name="subject" label={t('form.subject')} rules={[
              { required: true, whitespace: true, message: t('validation.required') },
              { validator: async (_, value) => {
                if (typeof value === 'string' && utf8Encoder.encode(value).byteLength > 2048) {
                  throw new Error(t('validation.subject'))
                }
              } },
            ]}>
              <Input />
            </Form.Item>
          ) : null}
          <Form.Item name="body" label={t(templateChannel === 'sms' ? 'form.smsBody' : 'form.body')} rules={[
            { required: true, whitespace: true, message: t('validation.required') },
            { validator: async (_, value) => {
              const maximum = templateChannel === 'sms' ? 8192 : 131072
              if (typeof value === 'string' && utf8Encoder.encode(value).byteLength > maximum) {
                throw new Error(t(templateChannel === 'sms' ? 'validation.smsBody' : 'validation.body'))
              }
            } },
          ]}>
            <Input.TextArea rows={6} />
          </Form.Item>
          <Form.Item name="variables_text" label={t('templates.variables')} rules={[
            { pattern: /^(?:[a-z][a-z0-9_]{0,63}(?:\s*,\s*[a-z][a-z0-9_]{0,63})*)?$/, message: t('validation.variables') },
          ]}>
            <Input placeholder={t('form.variablesPlaceholder')} />
          </Form.Item>
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button disabled={templateSaving || locked} onClick={() => setTemplateOpen(false)}>{t('actions.cancel')}</Button>
            <Button type="primary" htmlType="submit" loading={templateSaving}>{t('actions.createTemplate')}</Button>
          </Space>
        </Form>
      </Modal>
      <DeliveryLogsDrawer
        accessToken={accessToken}
        ownerKey={`${scopeID}:${sessionEpoch}`}
        open={deliveryOpen}
        onClose={() => setDeliveryOpen(false)}
        t={t}
      />
    </>
  )
}

function DeliveryLogsDrawer({ accessToken, ownerKey, open, onClose, t }: {
  accessToken: string
  ownerKey: string
  open: boolean
  onClose: () => void
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const { i18n } = useTranslation('notificationSettings')
  const accessTokenRef = useRef(accessToken)
  accessTokenRef.current = accessToken
  const [pageIndex, setPageIndex] = useState(0)
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined])
  const [selectedOutboxID, setSelectedOutboxID] = useState<string | null>(null)
  const cursor = cursors[pageIndex]
  const deliveryQuery = useQuery({
    queryKey: ['notification-deliveries', ownerKey, cursor],
    queryFn: () => notificationsApi.listDeliveries(accessTokenRef.current, {
      limit: 20, ...(cursor ? { cursor } : {}),
    }),
    enabled: open,
  })
  const attemptQuery = useQuery({
    queryKey: ['notification-delivery-attempts', ownerKey, selectedOutboxID],
    queryFn: () => notificationsApi.listDeliveryAttempts(accessTokenRef.current, selectedOutboxID!),
    enabled: open && selectedOutboxID !== null,
  })
  const nextPage = () => {
    const next = deliveryQuery.data?.next_cursor
    if (!next) return
    setCursors((current) => [...current.slice(0, pageIndex + 1), next])
    setPageIndex((current) => current + 1)
    setSelectedOutboxID(null)
  }
  const previousPage = () => {
    setPageIndex((current) => Math.max(0, current - 1))
    setSelectedOutboxID(null)
  }
  const formatTime = (value?: string) => value
    ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value))
    : t('deliveries.values.empty')
  const deliveryColumns: TableColumnsType<NotificationDeliveryLog> = [
    { title: t('deliveries.columns.channel'), dataIndex: 'channel', width: 90, render: (value: string) => t(`deliveries.channels.${value}`) },
    { title: t('deliveries.columns.state'), dataIndex: 'state', width: 120, render: (value: string) => <Tag>{t(`deliveries.states.${value}`)}</Tag> },
    { title: t('deliveries.columns.attempts'), dataIndex: 'attempt_count', width: 90 },
    { title: t('deliveries.columns.failure'), dataIndex: 'failure_code', width: 180, render: (value?: string) => value || t('deliveries.values.empty') },
    { title: t('deliveries.columns.createdAt'), dataIndex: 'created_at', width: 190, render: formatTime },
    { title: t('deliveries.columns.actions'), key: 'actions', fixed: 'right', width: 130, render: (_, item) => (
      <Button size="small" icon={<ListChecks size={14} />} onClick={() => setSelectedOutboxID(item.outbox_id)}>
        {t('deliveries.actions.attempts')}
      </Button>
    ) },
  ]
  const attemptColumns: TableColumnsType<NotificationDeliveryAttempt> = [
    { title: t('deliveries.attempts.number'), dataIndex: 'attempt_number', width: 100, render: (value: number) => t('deliveries.attempts.numberValue', { number: value }) },
    { title: t('deliveries.attempts.outcome'), dataIndex: 'outcome', width: 150, render: (value: string) => t(`deliveries.outcomes.${value}`) },
    { title: t('deliveries.columns.failure'), dataIndex: 'failure_code', width: 180, render: (value?: string) => value || t('deliveries.values.empty') },
    { title: t('deliveries.attempts.claimedAt'), dataIndex: 'claimed_at', width: 190, render: formatTime },
    { title: t('deliveries.attempts.completedAt'), dataIndex: 'completed_at', width: 190, render: formatTime },
  ]
  return (
    <Drawer open={open} width={960} title={t('deliveries.title')} onClose={onClose} destroyOnHidden>
      <Space direction="vertical" size={16} style={{ width: '100%', minWidth: 0 }}>
        {deliveryQuery.error ? (
          <Alert type="error" showIcon message={t('errors.loadFailed')} action={(
            <Button icon={<RefreshCw size={14} />} onClick={() => { void deliveryQuery.refetch() }}>{t('deliveries.actions.retry')}</Button>
          )} />
        ) : (
          <>
            <Table
              rowKey="outbox_id"
              size="small"
              loading={deliveryQuery.isPending || deliveryQuery.isFetching}
              columns={deliveryColumns}
              dataSource={deliveryQuery.data?.items ?? []}
              pagination={false}
              scroll={{ x: 900 }}
              locale={{ emptyText: deliveryQuery.isPending ? ' ' : t('deliveries.empty') }}
            />
            <Space>
              <Button aria-label={t('deliveries.actions.previous')} icon={<ChevronLeft size={14} />} disabled={pageIndex === 0 || deliveryQuery.isFetching} onClick={previousPage} />
              <Typography.Text>{t('deliveries.page', { page: pageIndex + 1 })}</Typography.Text>
              <Button aria-label={t('deliveries.actions.next')} icon={<ChevronRight size={14} />} disabled={!deliveryQuery.data?.next_cursor || deliveryQuery.isFetching} onClick={nextPage} />
            </Space>
          </>
        )}
        {selectedOutboxID ? (
          <section aria-label={t('deliveries.attempts.title')}>
            <Typography.Title level={5}>{t('deliveries.attempts.title')}</Typography.Title>
            {attemptQuery.error ? (
              <Alert type="error" showIcon message={t('errors.loadFailed')} action={(
                <Button icon={<RefreshCw size={14} />} onClick={() => { void attemptQuery.refetch() }}>{t('deliveries.actions.retry')}</Button>
              )} />
            ) : (
              <Table
                rowKey="attempt_number"
                size="small"
                loading={attemptQuery.isPending || attemptQuery.isFetching}
                columns={attemptColumns}
                dataSource={attemptQuery.data?.items ?? []}
                pagination={false}
                scroll={{ x: 760 }}
                locale={{ emptyText: attemptQuery.isPending ? ' ' : t('deliveries.attempts.empty') }}
              />
            )}
          </section>
        ) : null}
      </Space>
    </Drawer>
  )
}

function isDeterministicWriteError(error: ApiError) {
  return error.status === 400 || error.status === 403 || error.status === 409
}

function errorResult(
  error: ApiError,
  t: (key: string, options?: Record<string, unknown>) => string,
  retry: () => void,
) {
  if (error.status === 403 || error.code === 'notification_permission_denied') {
    return <Result status="403" title="403" subTitle={t('errors.forbidden')} />
  }
  return (
    <Result
      status="error"
      title={t('errors.loadFailed')}
      subTitle={t('errors.requestFailed', { requestId: error.requestId ?? t('values.unknownRequest') })}
      extra={<Button icon={<RefreshCw size={14} />} onClick={retry}>{t('common:retry')}</Button>}
    />
  )
}

function errorText(error: ApiError, t: (key: string, options?: Record<string, unknown>) => string) {
  if (error.status === 429 || error.code === 'rate_limited') return t('errors.rateLimited')
  if (error.code === 'notification_channel_unsupported') return t('errors.unsupported')
  if (error.code === 'version_conflict') return t('errors.versionConflict')
  if (error.code === 'template_version_conflict') return t('errors.templateVersionConflict')
  if (error.status === 403 || error.code === 'notification_permission_denied') return t('errors.forbidden')
  if (error.status === 400) return t('errors.validation')
  if (error.status === 409) return t('errors.versionConflict')
  return t('errors.writeFailed')
}
